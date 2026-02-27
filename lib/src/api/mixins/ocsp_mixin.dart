import 'dart:typed_data';

import '../openssl.dart';
import '../openssl_context.dart';
import '../../crypto/evp_pkey.dart';
import '../../ocsp/ocsp_client.dart';
import '../../ocsp/ocsp_response_builder.dart';
import '../../x509/x509_certificate.dart';

/// Mixin for OCSP response generation.
mixin OcspMixin on OpenSslContext {
  /// Builds a DER-encoded OCSP request for [certificate]/[issuerCertificate].
  ///
  /// [hashAlgorithm] defaults to SHA1 to match OpenSSL CLI behavior.
  /// Set [nonceLength] > 0 to include a nonce.
  Uint8List buildOcspRequest({
    required X509Certificate certificate,
    required X509Certificate issuerCertificate,
    String hashAlgorithm = 'SHA1',
    int? nonceLength,
  }) {
    final client = OcspClient(this as OpenSSL);
    return client.buildRequestDer(
      certificate: certificate.handle,
      issuerCertificate: issuerCertificate.handle,
      hashAlgorithm: hashAlgorithm,
      nonceLength: nonceLength,
    );
  }

  /// Reads OCSP response status for [certificate]/[issuerCertificate].
  OcspCertificateStatusResult readOcspResponseStatus({
    required Uint8List responseDer,
    required X509Certificate certificate,
    required X509Certificate issuerCertificate,
    String hashAlgorithm = 'SHA1',
    bool requireSuccessfulResponse = true,
  }) {
    final client = OcspClient(this as OpenSSL);
    return client.readResponseStatus(
      responseDer: responseDer,
      certificate: certificate.handle,
      issuerCertificate: issuerCertificate.handle,
      hashAlgorithm: hashAlgorithm,
      requireSuccessfulResponse: requireSuccessfulResponse,
    );
  }

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
      extraCertificates:
          extraCertificates?.map((cert) => cert.handle).toList(growable: false),
      hashAlgorithm: hashAlgorithm,
      defaultThisUpdate: defaultThisUpdate,
      defaultNextUpdate: defaultNextUpdate,
      includeNonce: includeNonce,
      noncePolicy: noncePolicy,
      responderIdByKey: responderIdByKey,
    );
  }
}
