import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import 'x509_certificate.dart';
import 'x509_name.dart';
import 'x509_request.dart';

/// Builder for X509 Certificates.
class X509CertificateBuilder {
  final OpenSSL _context;
  final Pointer<X509> _cert;

  X509CertificateBuilder(this._context) : _cert = _context.bindings.X509_new() {
    if (_cert == nullptr) {
      throw OpenSslException('Failed to create X509 structure');
    }
    // Set version to V3 (which is integer 2)
    _context.bindings.X509_set_version(_cert, 2);
    // Set default serial number (1)
    _setSerial(1);
  }

  void _setSerial(int serial) {
    final asn1Int = _context.bindings.ASN1_INTEGER_new();
    _context.bindings.ASN1_INTEGER_set(asn1Int, serial);
    _context.bindings.X509_set_serialNumber(_cert, asn1Int);
    _context.bindings.ASN1_INTEGER_free(asn1Int);
  }

  /// Sets the serial number.
  void setSerialNumber(int serial) {
    _setSerial(serial);
  }

  /// Sets the validity period in seconds from now.
  void setValidity({int notBeforeOffset = 0, int notAfterOffset = 31536000}) {
    final notBefore = _context.bindings.X509_getm_notBefore(_cert);
    final notAfter = _context.bindings.X509_getm_notAfter(_cert);
    
    _context.bindings.X509_gmtime_adj(notBefore, notBeforeOffset);
    _context.bindings.X509_gmtime_adj(notAfter, notAfterOffset);
  }

  /// Sets the Subject DN (Distinguished Name).
  /// Example: `builder.setSubject(commonName: 'My Cert', organization: 'My Org')`
  void setSubject({
    String? commonName,
    String? organization,
    String? country,
    String? locality,
    String? state,
    String? unit,
  }) {
    // X509_get_subject_name returns an internal pointer, do NOT free it.
    final namePtr = _context.bindings.X509_get_subject_name(_cert);
    final name = X509Name(namePtr, _context, isOwned: false);
    
    if (commonName != null) name.addEntry('CN', commonName);
    if (organization != null) name.addEntry('O', organization);
    if (country != null) name.addEntry('C', country);
    if (locality != null) name.addEntry('L', locality);
    if (state != null) name.addEntry('ST', state);
    if (unit != null) name.addEntry('OU', unit);
  }

  /// Sets the Issuer DN.
  /// For self-signed certificates, this should be same as Subject.
  /// If [issuerCert] is provided, copies name from it.
  void setIssuer({
      String? commonName,
      String? organization,
      String? country,
      X509Certificate? issuerCert
  }) {
      final namePtr = _context.bindings.X509_get_issuer_name(_cert);
      
      if (issuerCert != null) {
          // Copy from issuer cert
           final issuerNamePtr = _context.bindings.X509_get_subject_name(issuerCert.handle);
           // X509_set_issuer_name copies the content
           if (_context.bindings.X509_set_issuer_name(_cert, issuerNamePtr) != 1) {
               throw OpenSslException('Failed to set issuer name from certificate');
           }
           return;
      }
      
      final name = X509Name(namePtr, _context, isOwned: false);
      if (commonName != null) name.addEntry('CN', commonName);
      if (organization != null) name.addEntry('O', organization);
      if (country != null) name.addEntry('C', country);
  }
  
  /// Helper for Self-Signed: Sets Issuer = Subject.
  void setIssuerAsSubject() {
     final subjectPtr = _context.bindings.X509_get_subject_name(_cert);
     if (_context.bindings.X509_set_issuer_name(_cert, subjectPtr) != 1) {
         throw OpenSslException('Failed to set issuer as subject');
     }
  }

  /// Sets the Subject DN from a CSR.
  void setSubjectFromCsr(X509Request csr) {
    final namePtr = _context.bindings.X509_REQ_get_subject_name(csr.handle);
    if (_context.bindings.X509_set_subject_name(_cert, namePtr) != 1) {
       throw OpenSslException('Failed to set subject from CSR');
    }
  }

  /// Sets the Public Key from a CSR.
  void setPublicKeyFromCsr(X509Request csr) {
    final pkey = _context.bindings.X509_REQ_get_pubkey(csr.handle);
    if (pkey == nullptr) {
      throw OpenSslException('Failed to get public key from CSR');
    }

    try {
      if (_context.bindings.X509_set_pubkey(_cert, pkey) != 1) {
         throw OpenSslException('Failed to set public key from CSR');
      }
    } finally {
      _context.bindings.EVP_PKEY_free(pkey);
    }
  }

  /// Sets the Public Key.
  void setPublicKey(EvpPkey key) {
    if (_context.bindings.X509_set_pubkey(_cert, key.handle) != 1) {
      throw OpenSslException('Failed to set public key');
    }
  }

  /// Signs the certificate with a Private Key and returns the certificate wrapper.
  /// [hashAlgorithm] defaults to SHA256.
  X509Certificate sign(EvpPkey privateKey, {String hashAlgorithm = 'SHA256'}) {
    // We need EVP_MD* for the algorithm
     final digestName = hashAlgorithm.toNativeUtf8();
     final md = _context.bindings.EVP_get_digestbyname(digestName.cast());
     calloc.free(digestName);

     if (md == nullptr) {
       // OpenSSL cleanup handled by X509_free if we throw? 
       // We haven't returned the cert yet, so the builder owns it essentially.
       // But if we throw, connection is lost.
       // We should free _cert if we are failing completely or let user reuse builder?
       throw OpenSslException('Unknown digest algorithm: $hashAlgorithm');
     }

     if (_context.bindings.X509_sign(_cert, privateKey.handle, md) == 0) {
        throw OpenSslException('Failed to sign certificate'); 
     }

     // Transfer ownership to the wrapper
     return X509Certificate(_cert, _context);
  }
}
