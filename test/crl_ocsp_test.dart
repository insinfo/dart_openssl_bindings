import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/ocsp/ocsp_response_builder.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';
import 'package:openssl_bindings/src/generated/ffi.dart';
import 'package:test/test.dart';

void main() {
  group('CRL & OCSP', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Should build and sign CRL', () {
      final caKey = openSsl.generateRsa(2048);
      final caCert = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Test Root CA', organization: 'Test')
        ..setIssuerAsSubject()
        ..setPublicKey(caKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: true, critical: true)
        ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true);
      final issuerCert = caCert.sign(caKey);

      final now = DateTime.now().toUtc();
      final crlBuilder = openSsl.newCrlBuilder()
        ..setIssuerFromCertificate(issuerCert)
        ..setUpdateTimes(
          thisUpdate: now,
          nextUpdate: now.add(const Duration(hours: 24)),
        )
        ..addRevokedSerial(
          serialNumber: 1234,
          revocationTime: now,
        );

      final crl = crlBuilder.sign(issuerKey: caKey, hashAlgorithm: 'SHA256');
      final pem = crl.toPem();
      final der = crl.toDer();

      expect(pem, contains('BEGIN X509 CRL'));
      expect(der, isNotEmpty);
      expect(der.first, equals(0x30));
    });

    test('Should build OCSP response for request', () {
      final caKey = openSsl.generateRsa(2048);
      final caBuilder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Test Root CA', organization: 'Test')
        ..setIssuerAsSubject()
        ..setPublicKey(caKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: true, critical: true)
        ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true);
      final caCert = caBuilder.sign(caKey);

      final leafKey = openSsl.generateRsa(2048);
      final leafBuilder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Leaf', organization: 'Test')
        ..setIssuer(issuerCert: caCert)
        ..setPublicKey(leafKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: false, critical: true)
        ..addKeyUsage(digitalSignature: true, keyEncipherment: true, critical: true);
      final leafCert = leafBuilder.sign(caKey);

      final requestDer = _buildOcspRequest(openSsl, leafCert.handle, caCert.handle);
      final serial = leafCert.serialNumber;

      final responseDer = openSsl.buildOcspResponse(
        requestDer: requestDer,
        statusBySerial: {
          serial: const OcspStatusInfo(status: OcspCertStatus.good),
        },
        responderCertificate: caCert,
        responderKey: caKey,
        hashAlgorithm: 'SHA256',
      );

      expect(responseDer, isNotEmpty);
      expect(responseDer.first, equals(0x30));
    });
  });
}

Uint8List _buildOcspRequest(
  OpenSSL openSsl,
  Pointer<X509> subject,
  Pointer<X509> issuer,
) {
  final bindings = openSsl.bindings;

  final request = bindings.OCSP_REQUEST_new();
  if (request == nullptr) {
    throw StateError('Failed to create OCSP request');
  }

  try {
    final md = bindings.EVP_sha1();
    if (md == nullptr) {
      throw StateError('EVP_sha1 returned null');
    }

    final certId = bindings.OCSP_cert_to_id(md, subject, issuer);
    if (certId == nullptr) {
      throw StateError('Failed to create OCSP CERTID');
    }

    final oneReq = bindings.OCSP_request_add0_id(request, certId);
    if (oneReq == nullptr) {
      bindings.OCSP_CERTID_free(certId);
      throw StateError('Failed to add CERTID to OCSP request');
    }

    final len = bindings.i2d_OCSP_REQUEST(request, nullptr);
    if (len <= 0) {
      throw StateError('Failed to get OCSP request length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = bindings.i2d_OCSP_REQUEST(request, out);
      if (written <= 0) {
        throw StateError('Failed to encode OCSP request');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  } finally {
    bindings.OCSP_REQUEST_free(request);
  }
}