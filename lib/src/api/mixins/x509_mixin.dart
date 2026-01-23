import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../openssl_context.dart';
import '../../api/openssl.dart';
import '../../infra/ssl_exception.dart';
import '../../x509/x509_certificate.dart';
import '../../x509/x509_builder.dart';
import 'bio_mixin.dart';

/// Mixin for X509 Certificate operations.
mixin X509Mixin on OpenSslContext, BioMixin {

  /// Creates a new Builder for creating and signing X509 Certificates.
  X509CertificateBuilder newCertificateBuilder() {
    // Cast to OpenSSL is safe as OpenSSL implements OpenSslContext and mixes this in.
    return X509CertificateBuilder(this as OpenSSL);
  }

  /// Loads an X509 Certificate from PEM string.
  X509Certificate loadCertificatePem(String pem) {
    final bio = createBioFromString(pem);
    try {
      final cert = bindings.PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
      if (cert == nullptr) {
        throw OpenSslException('Failed to read certificate from PEM');
      }
      return X509Certificate(cert, this as dynamic);
    } finally {
      freeBio(bio);
    }
  }

  /// Loads an X509 Certificate from DER bytes.
  X509Certificate loadCertificateDer(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final inOutPtr = calloc<Pointer<UnsignedChar>>();
    inOutPtr.value = dataPtr.cast<UnsignedChar>();

    try {
      final cert = bindings.d2i_X509(nullptr, inOutPtr, der.length);
      if (cert == nullptr) {
        throw OpenSslException('Failed to read certificate from DER');
      }
      return X509Certificate(cert, this as dynamic);
    } finally {
      calloc.free(inOutPtr);
      calloc.free(dataPtr);
    }
  }

  /// Loads an X509 Certificate from bytes (auto-detect PEM vs DER).
  X509Certificate loadCertificateBytes(Uint8List bytes) {
    if (_looksLikePem(bytes)) {
      return loadCertificatePem(String.fromCharCodes(bytes));
    }
    return loadCertificateDer(bytes);
  }

  /// Encodes an X509 Certificate to DER bytes.
  Uint8List encodeCertificateDer(X509Certificate cert) {
    final len = bindings.i2d_X509(cert.handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get DER length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = bindings.i2d_X509(cert.handle, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode certificate to DER');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  /// Encodes an X509 Certificate to PEM string.
  String encodeCertificatePem(X509Certificate cert) {
    final bio = createBio();
    try {
      final result = bindings.PEM_write_bio_X509(bio, cert.handle);
      if (result != 1) {
        throw OpenSslException('Failed to write certificate to PEM');
      }
      return bioToString(bio);
    } finally {
      freeBio(bio);
    }
  }

  /// Splits a PEM chain into individual PEM certificate blocks.
  List<String> splitPemChain(String pemChain) {
    final matches = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
    ).allMatches(pemChain);

    final blocks = <String>[];
    for (final match in matches) {
      final block = match.group(0);
      if (block != null && block.trim().isNotEmpty) {
        blocks.add(block.trim());
      }
    }
    return blocks.isEmpty ? [pemChain.trim()] : blocks;
  }

  /// Loads a list of certificates from a PEM chain string.
  List<X509Certificate> loadCertificatesFromPemChain(String pemChain) {
    final blocks = splitPemChain(pemChain);
    return blocks.map(loadCertificatePem).toList();
  }

  /// Converts a PEM chain string into a list of DER-encoded certificates.
  List<Uint8List> convertPemChainToDerList(String pemChain) {
    final blocks = splitPemChain(pemChain);
    return blocks.map(convertCertificatePemToDer).toList();
  }

  /// Converts a PEM certificate into DER bytes.
  Uint8List convertCertificatePemToDer(String pem) {
    final cert = loadCertificatePem(pem);
    return encodeCertificateDer(cert);
  }

  /// Converts a DER certificate into PEM string.
  String convertCertificateDerToPem(Uint8List der) {
    final cert = loadCertificateDer(der);
    return encodeCertificatePem(cert);
  }

  bool _looksLikePem(Uint8List bytes) {
    final text = String.fromCharCodes(bytes);
    return text.contains('-----BEGIN CERTIFICATE-----') ||
        text.contains('-----BEGIN X509 CERTIFICATE-----');
  }

  /// Creates a new empty X509 Certificate structure.
  /// Useful for building new certificates.
  X509Certificate createCertificate() {
     final cert = bindings.X509_new();
     if (cert == nullptr) {
       throw OpenSslException('Failed to create X509 structure');
     }
     return X509Certificate(cert, this as dynamic);
  }
}
