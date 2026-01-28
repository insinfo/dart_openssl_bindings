import 'dart:typed_data';

import '../openssl.dart';
import '../openssl_context.dart';
import '../../crypto/evp_pkey.dart';
import '../../ocsp/ocsp_response_builder.dart';
import '../../x509/x509_certificate.dart';

/// Mixin for OCSP response generation.
mixin OcspMixin on OpenSslContext {
  /// Builds a DER-encoded OCSP response for the given request.
  Uint8List buildOcspResponse({
    required Uint8List requestDer,
    required Map<String, OcspStatusInfo> statusBySerial,
    required X509Certificate responderCertificate,
    required EvpPkey responderKey,
    List<X509Certificate>? extraCertificates,
    String hashAlgorithm = 'SHA256',
    DateTime? defaultThisUpdate,
    DateTime? defaultNextUpdate,
    bool includeNonce = true,
    OcspNoncePolicy? noncePolicy,
    bool responderIdByKey = false,
  }) {
    final builder = OcspResponseBuilder(this as OpenSSL);
    return builder.buildDer(
      requestDer: requestDer,
      statusBySerial: statusBySerial,
      responderCert: responderCertificate.handle,
      responderKey: responderKey,
      extraCertificates: extraCertificates
          ?.map((cert) => cert.handle)
          .toList(growable: false),
      hashAlgorithm: hashAlgorithm,
      defaultThisUpdate: defaultThisUpdate,
      defaultNextUpdate: defaultNextUpdate,
      includeNonce: includeNonce,
      noncePolicy: noncePolicy,
      responderIdByKey: responderIdByKey,
    );
  }
}