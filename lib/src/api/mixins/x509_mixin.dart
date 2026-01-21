import 'dart:ffi';
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
