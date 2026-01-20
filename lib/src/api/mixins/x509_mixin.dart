import 'dart:ffi';
import '../openssl_context.dart';
import '../../infra/ssl_exception.dart';
import '../../x509/x509_certificate.dart';
import 'bio_mixin.dart';

/// Mixin for X509 Certificate operations.
mixin X509Mixin on OpenSslContext, BioMixin {

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
