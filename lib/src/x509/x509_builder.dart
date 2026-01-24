//C:\MyDartProjects\openssl_bindings\lib\src\x509\x509_builder.dart
import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import 'x509_certificate.dart';
import 'x509_name.dart';
import 'x509_request.dart';
import 'x509_extensions.dart';

/// Builder for X509 Certificates.
class X509CertificateBuilder /*implements Finalizable*/ {
  final OpenSSL _context;
  final Pointer<X509> _cert;
  Pointer<X509>? _issuerCert;
  // late final NativeFinalizer _finalizer;
  bool _isDisposed = false;
  bool _isConsumed = false;

  X509CertificateBuilder(this._context) : _cert = _context.bindings.X509_new() {
    if (_cert == nullptr) {
      throw OpenSslException('Failed to create X509 structure');
    }
    print('DEBUG: X509CertificateBuilder created cert ${_cert.address.toRadixString(16)}');
    // final freePtr = _context.lookup<Void Function(Pointer<X509>)>('X509_free');
    // _finalizer = NativeFinalizer(freePtr.cast());
    // _finalizer.attach(this, _cert.cast(), detach: this);
    // Set version to V3 (which is integer 2)
    _context.bindings.X509_set_version(_cert, 2);
    // Set default serial number (1)
    _setSerial(1);
  }

  void _ensureUsable() {
    if (_isDisposed) {
      throw StateError('X509CertificateBuilder has been disposed');
    }
    if (_isConsumed) {
      throw StateError('X509CertificateBuilder already signed');
    }
  }

  void _setSerial(int serial) {
    final asn1Int = _context.bindings.ASN1_INTEGER_new();
    _context.bindings.ASN1_INTEGER_set(asn1Int, serial);
     print('DEBUG: X509CertificateBuilder setting serial $serial');
    final res = _context.bindings.X509_set_serialNumber(_cert, asn1Int);
    
    // Always free the temporary ASN1_INTEGER, as X509_set_serialNumber duplicates it.
    _context.bindings.ASN1_INTEGER_free(asn1Int);

    if (res != 1) {
      throw OpenSslException('Failed to set serial number');
    }
  }

  /// Sets the serial number.
  void setSerialNumber(int serial) {
    _ensureUsable();
    _setSerial(serial);
  }

  /// Sets the validity period in seconds from now.
  void setValidity({int notBeforeOffset = 0, int notAfterOffset = 31536000}) {
    _ensureUsable();
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
    _ensureUsable();
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
      _ensureUsable();
      final namePtr = _context.bindings.X509_get_issuer_name(_cert);
      
      if (issuerCert != null) {
          _issuerCert = issuerCert.handle;
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
      _ensureUsable();
     final subjectPtr = _context.bindings.X509_get_subject_name(_cert);
     if (_context.bindings.X509_set_issuer_name(_cert, subjectPtr) != 1) {
         throw OpenSslException('Failed to set issuer as subject');
     }
     _issuerCert = _cert;
  }

  /// Adds Subject Alternative Name (otherName) entries.
  ///
  /// Values are encoded as UTF8 strings.
  void addSubjectAltNameOtherNames(List<X509OtherName> otherNames) {
    _ensureUsable();
    if (otherNames.isEmpty) return;

    final parts = otherNames
        .map((item) => 'otherName:${item.oid};UTF8:${item.value}')
        .join(',');
    _addExtensionByName('subjectAltName', parts);
  }

  /// Adds CRL Distribution Points URLs.
  void addCrlDistributionPoints(List<String> urls) {
    _ensureUsable();
    if (urls.isEmpty) return;

    final parts = urls.map((url) => 'URI:$url').join(',');
    _addExtensionByName('crlDistributionPoints', parts);
  }

  /// Adds OCSP URLs in Authority Information Access.
  void addOcspUrls(List<String> urls) {
    _ensureUsable();
    if (urls.isEmpty) return;

    final parts = urls.map((url) => 'OCSP;URI:$url').join(',');
    _addExtensionByName('authorityInfoAccess', parts);
  }

  /// Adds Certificate Policies by OID.
  void addCertificatePolicies(List<String> policyOids) {
    _ensureUsable();
    if (policyOids.isEmpty) return;

    final der = _encodeCertificatePolicies(policyOids);
    _addCertificatePoliciesExtension('2.5.29.32', der);
  }

  /// Adds Basic Constraints extension (2.5.29.19).
  void addBasicConstraints({
    required bool isCa,
    int? pathLen,
    bool critical = false,
  }) {
    _ensureUsable();

    final parts = <String>[];
    if (critical) parts.add('critical');
    parts.add(isCa ? 'CA:TRUE' : 'CA:FALSE');
    if (isCa && pathLen != null) {
      parts.add('pathlen:$pathLen');
    }

    _addExtensionByName('basicConstraints', parts.join(','));
  }

  /// Adds Key Usage extension (2.5.29.15).
  void addKeyUsage({
    bool digitalSignature = false,
    bool nonRepudiation = false,
    bool keyEncipherment = false,
    bool dataEncipherment = false,
    bool keyAgreement = false,
    bool keyCertSign = false,
    bool cRLSign = false,
    bool encipherOnly = false,
    bool decipherOnly = false,
    bool critical = false,
  }) {
    _ensureUsable();

    final usages = <String>[];
    if (digitalSignature) usages.add('digitalSignature');
    if (nonRepudiation) usages.add('nonRepudiation');
    if (keyEncipherment) usages.add('keyEncipherment');
    if (dataEncipherment) usages.add('dataEncipherment');
    if (keyAgreement) usages.add('keyAgreement');
    if (keyCertSign) usages.add('keyCertSign');
    if (cRLSign) usages.add('cRLSign');
    if (encipherOnly) usages.add('encipherOnly');
    if (decipherOnly) usages.add('decipherOnly');

    if (usages.isEmpty) return;
    final parts = [if (critical) 'critical', ...usages].join(',');
    _addExtensionByName('keyUsage', parts);
  }

  /// Adds Extended Key Usage extension (2.5.29.37).
  ///
  /// Common values: serverAuth, clientAuth, codeSigning, emailProtection,
  /// timeStamping, OCSPSigning, or explicit OIDs.
  void addExtendedKeyUsage(
    List<String> usages, {
    bool critical = false,
  }) {
    _ensureUsable();
    if (usages.isEmpty) return;

    final normalized = usages
        .map((u) => u.trim())
        .where((u) => u.isNotEmpty)
        .toList(growable: false);
    if (normalized.isEmpty) return;

    final parts = [if (critical) 'critical', ...normalized].join(',');
    _addExtensionByName('extendedKeyUsage', parts);
  }

  void _addExtensionByName(String name, String value) {
    _ensureUsable();
    final ctx = calloc<X509V3_CTX>();
    try {
      final issuer = _issuerCert ?? _cert;
      _context.bindings.X509V3_set_ctx(ctx, issuer, _cert, nullptr, nullptr, 0);

      final namePtr = name.toNativeUtf8(allocator: calloc);
      final valuePtr = value.toNativeUtf8(allocator: calloc);

      try {
        final nid = _context.bindings.OBJ_txt2nid(namePtr.cast());
        final ext = nid > 0
            ? _context.bindings.X509V3_EXT_conf_nid(
                nullptr,
                ctx,
                nid,
                valuePtr.cast(),
              )
            : _context.bindings.X509V3_EXT_nconf(
                nullptr,
                ctx,
                namePtr.cast(),
                valuePtr.cast(),
              );
        if (ext == nullptr) {
          throw OpenSslException('Failed to create X509 extension: $name');
        }

        if (_context.bindings.X509_add_ext(_cert, ext, -1) != 1) {
          _context.bindings.X509_EXTENSION_free(ext);
          throw OpenSslException('Failed to add X509 extension: $name');
        }

        _context.bindings.X509_EXTENSION_free(ext);
      } finally {
        calloc.free(namePtr);
        calloc.free(valuePtr);
      }
    } finally {
      calloc.free(ctx);
    }
  }

  void _addCertificatePoliciesExtension(String oid, Uint8List der) {
    _ensureUsable();
    final oidPtr = oid.toNativeUtf8(allocator: calloc);
    Pointer<ASN1_OBJECT> obj = nullptr;
    Pointer<ASN1_OCTET_STRING> octet = nullptr;
    Pointer<X509_EXTENSION> ext = nullptr;
    Pointer<Uint8> dataPtr = nullptr;

    try {
      obj = _context.bindings.OBJ_txt2obj(oidPtr.cast(), 1);
      if (obj == nullptr) {
        throw OpenSslException('Failed to create ASN1 object for OID: $oid');
      }

      octet = _context.bindings.ASN1_OCTET_STRING_new();
      if (octet == nullptr) {
        throw OpenSslException('Failed to allocate ASN1 OCTET STRING');
      }

      dataPtr = calloc<Uint8>(der.length);
      dataPtr.asTypedList(der.length).setAll(0, der);

      if (_context.bindings.ASN1_OCTET_STRING_set(
            octet,
            dataPtr.cast<UnsignedChar>(),
            der.length,
          ) !=
          1) {
        throw OpenSslException(
          'Failed to set DER data for certificatePolicies',
        );
      }

      ext = _context.bindings.X509_EXTENSION_create_by_OBJ(
        nullptr,
        obj,
        0,
        octet,
      );
      if (ext == nullptr) {
        throw OpenSslException('Failed to create X509 extension: $oid');
      }

      if (_context.bindings.X509_add_ext(_cert, ext, -1) != 1) {
        throw OpenSslException('Failed to add X509 extension: $oid');
      }
    } finally {
      if (ext != nullptr) {
        _context.bindings.X509_EXTENSION_free(ext);
      }
      if (octet != nullptr) {
        _context.bindings.ASN1_OCTET_STRING_free(octet);
      }
      if (obj != nullptr) {
        _context.bindings.ASN1_OBJECT_free(obj);
      }
      if (dataPtr != nullptr) {
        calloc.free(dataPtr);
      }
      calloc.free(oidPtr);
    }
  }

  Uint8List _encodeCertificatePolicies(List<String> policyOids) {
    final content = <int>[];
    for (final oid in policyOids) {
      final oidTlv = _encodeOidTlv(oid);
      final policySeq = _encodeSequence(oidTlv);
      content.addAll(policySeq);
    }

    return Uint8List.fromList(_encodeSequence(content));
  }

  List<int> _encodeOidTlv(String oid) {
    final oidBytes = _encodeOidBytes(oid);
    return <int>[
      0x06,
      ..._encodeLength(oidBytes.length),
      ...oidBytes,
    ];
  }

  List<int> _encodeSequence(List<int> content) {
    return <int>[
      0x30,
      ..._encodeLength(content.length),
      ...content,
    ];
  }

  List<int> _encodeLength(int length) {
    if (length < 0x80) {
      return <int>[length];
    }

    final bytes = <int>[];
    var value = length;
    while (value > 0) {
      bytes.insert(0, value & 0xff);
      value >>= 8;
    }

    return <int>[0x80 | bytes.length, ...bytes];
  }

  List<int> _encodeOidBytes(String oid) {
    final parts = oid.split('.').map(int.parse).toList();
    if (parts.length < 2) {
      throw OpenSslException('Invalid OID: $oid');
    }

    final first = parts[0];
    final second = parts[1];
    if (first < 0 || first > 2 || second < 0 || second > 39) {
      throw OpenSslException('Invalid OID: $oid');
    }

    final bytes = <int>[40 * first + second];
    for (var i = 2; i < parts.length; i++) {
      bytes.addAll(_encodeBase128(parts[i]));
    }

    return bytes;
  }

  List<int> _encodeBase128(int value) {
    if (value == 0) return <int>[0];

    final bytes = <int>[];
    var current = value;
    while (current > 0) {
      bytes.insert(0, current & 0x7f);
      current >>= 7;
    }

    for (var i = 0; i < bytes.length - 1; i++) {
      bytes[i] |= 0x80;
    }

    return bytes;
  }


  /// Sets the Subject DN from a CSR.
  void setSubjectFromCsr(X509Request csr) {
    _ensureUsable();
    final namePtr = _context.bindings.X509_REQ_get_subject_name(csr.handle);
    if (_context.bindings.X509_set_subject_name(_cert, namePtr) != 1) {
       throw OpenSslException('Failed to set subject from CSR');
    }
  }

  /// Sets the Public Key from a CSR.
  void setPublicKeyFromCsr(X509Request csr) {
    _ensureUsable();
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
    _ensureUsable();
    if (_context.bindings.X509_set_pubkey(_cert, key.handle) != 1) {
      throw OpenSslException('Failed to set public key');
    }
  }

  /// Signs the certificate with a Private Key and returns the certificate wrapper.
  /// [hashAlgorithm] defaults to SHA256.
  X509Certificate sign(EvpPkey privateKey, {String hashAlgorithm = 'SHA256'}) {
    _ensureUsable();
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
        final err = _context.bindings.ERR_get_error();
        final strPtr = _context.bindings.ERR_error_string(err, nullptr);
        final errMsg = strPtr == nullptr ? 'Unknown error' : strPtr.cast<Utf8>().toDartString();
        throw OpenSslException('Failed to sign certificate: $errMsg ($err)'); 
     }

     // _finalizer.detach(this);
     _isConsumed = true;

     // Transfer ownership to the wrapper
     return X509Certificate(_cert, _context);
  }

  /// Releases the underlying X509 structure if the builder was not consumed.
  void dispose() {
    if (_isDisposed || _isConsumed) return;
    print('DEBUG: X509CertificateBuilder dispose freeing cert ${_cert.address.toRadixString(16)}');
    // _finalizer.detach(this);
    _context.bindings.X509_free(_cert);
    _isDisposed = true;
  }
}
