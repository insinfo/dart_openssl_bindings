import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/infra/ssl_exception.dart';
import 'package:openssl_bindings/src/ocsp/ocsp_response_builder.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';
import 'package:openssl_bindings/src/x509/x509_crl_builder.dart';
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
        ..setAuthorityKeyIdentifierFromIssuer(issuerCert: issuerCert)
        ..setCrlNumber(number: 1)
        ..setDeltaCrlIndicator(baseCrlNumber: 1)
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

    test('Should add revoked entry with reason', () {
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
        ..addRevokedSerialWithReason(
          serialNumber: 42,
          revocationTime: now,
          reasonCode: CrlReason.keyCompromise,
        );

      final crl = crlBuilder.sign(issuerKey: caKey, hashAlgorithm: 'SHA256');
      final der = crl.toDer();
      expect(der, isNotEmpty);
      expect(der.first, equals(0x30));
    });

    test('Should support long serial APIs in CRL builder', () {
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
      final longSerial =
          BigInt.parse('1234567890ABCDEF1234567890ABCDEF', radix: 16);
      final longCrlNumber =
          BigInt.parse('11223344556677889900AABBCCDDEEFF', radix: 16);
      final longDeltaBase =
          BigInt.parse('FFEEDDCCBBAA00998877665544332211', radix: 16);

      final crlBuilder = openSsl.newCrlBuilder()
        ..setIssuerFromCertificate(issuerCert)
        ..setUpdateTimes(
          thisUpdate: now,
          nextUpdate: now.add(const Duration(hours: 24)),
        )
        ..setCrlNumberBigInt(number: longCrlNumber)
        ..setDeltaCrlIndicatorBigInt(baseCrlNumber: longDeltaBase)
        ..addRevokedSerialBigInt(
          serialNumber: longSerial,
          revocationTime: now,
        )
        ..addRevokedSerialWithReasonBigInt(
          serialNumber: longSerial + BigInt.one,
          revocationTime: now,
          reasonCode: CrlReason.superseded,
        )
        ..addRevokedSerialHex(
          serialHex: '0xA1B2C3D4E5F60718293A4B5C6D7E8F90',
          revocationTime: now,
        );

      final crl = crlBuilder.sign(issuerKey: caKey, hashAlgorithm: 'SHA256');
      final der = crl.toDer();
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
        ..addKeyUsage(
            digitalSignature: true, keyEncipherment: true, critical: true);
      final leafCert = leafBuilder.sign(caKey);

      final requestDer =
          _buildOcspRequest(openSsl, leafCert.handle, caCert.handle);
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

    test('Should build OCSP response with responderId by key and extra certs',
        () {
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
        ..addKeyUsage(
            digitalSignature: true, keyEncipherment: true, critical: true);
      final leafCert = leafBuilder.sign(caKey);

      final requestDer =
          _buildOcspRequest(openSsl, leafCert.handle, caCert.handle);

      final responseDer = openSsl.buildOcspResponse(
        requestDer: requestDer,
        statusBySerial: {
          leafCert.serialNumber:
              const OcspStatusInfo(status: OcspCertStatus.good),
        },
        responderCertificate: caCert,
        responderKey: caKey,
        extraCertificates: [caCert],
        responderIdByKey: true,
        hashAlgorithm: 'SHA256',
      );

      expect(responseDer, isNotEmpty);
      expect(responseDer.first, equals(0x30));
    });

    test('Should enforce OCSP nonce policy', () {
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
        ..addKeyUsage(
            digitalSignature: true, keyEncipherment: true, critical: true);
      final leafCert = leafBuilder.sign(caKey);

      final requestWithoutNonce =
          _buildOcspRequest(openSsl, leafCert.handle, caCert.handle);
      expect(
        () => openSsl.buildOcspResponse(
          requestDer: requestWithoutNonce,
          statusBySerial: {
            leafCert.serialNumber:
                const OcspStatusInfo(status: OcspCertStatus.good),
          },
          responderCertificate: caCert,
          responderKey: caKey,
          hashAlgorithm: 'SHA256',
          noncePolicy: OcspNoncePolicy.require,
        ),
        throwsA(isA<OpenSslException>()),
      );

      final requestWithNonce = _buildOcspRequest(
        openSsl,
        leafCert.handle,
        caCert.handle,
        includeNonce: true,
      );
      final responseDer = openSsl.buildOcspResponse(
        requestDer: requestWithNonce,
        statusBySerial: {
          leafCert.serialNumber:
              const OcspStatusInfo(status: OcspCertStatus.good),
        },
        responderCertificate: caCert,
        responderKey: caKey,
        hashAlgorithm: 'SHA256',
        noncePolicy: OcspNoncePolicy.require,
      );

      expect(responseDer, isNotEmpty);
      expect(responseDer.first, equals(0x30));
    });

    test('Should build and parse OCSP request/response without CLI', () {
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
        ..addKeyUsage(
          digitalSignature: true,
          keyEncipherment: true,
          critical: true,
        );
      final leafCert = leafBuilder.sign(caKey);

      final requestDer = openSsl.buildOcspRequest(
        certificate: leafCert,
        issuerCertificate: caCert,
        nonceLength: 16,
      );
      expect(requestDer, isNotEmpty);
      expect(requestDer.first, equals(0x30));

      final goodResponseDer = openSsl.buildOcspResponse(
        requestDer: requestDer,
        statusBySerial: {
          leafCert.serialNumber:
              const OcspStatusInfo(status: OcspCertStatus.good),
        },
        responderCertificate: caCert,
        responderKey: caKey,
      );

      final goodParsed = openSsl.readOcspResponseStatus(
        responseDer: goodResponseDer,
        certificate: leafCert,
        issuerCertificate: caCert,
      );
      expect(goodParsed.responseStatusCode, equals(0));
      expect(goodParsed.status, equals(OcspCertStatus.good));

      final now = DateTime.now().toUtc();
      final revokedResponseDer = openSsl.buildOcspResponse(
        requestDer: requestDer,
        statusBySerial: {
          leafCert.serialNumber: OcspStatusInfo(
            status: OcspCertStatus.revoked,
            revocationTime: now,
            revocationReason: OcspRevocationReason.keyCompromise,
          ),
        },
        responderCertificate: caCert,
        responderKey: caKey,
      );

      final revokedParsed = openSsl.readOcspResponseStatus(
        responseDer: revokedResponseDer,
        certificate: leafCert,
        issuerCertificate: caCert,
      );
      expect(revokedParsed.responseStatusCode, equals(0));
      expect(revokedParsed.status, equals(OcspCertStatus.revoked));
      expect(
        revokedParsed.revocationReason,
        equals(OcspRevocationReason.keyCompromise),
      );
      expect(revokedParsed.revocationTime, isNotNull);
    });

    test('Should load CRL and check revoked serials without CLI', () {
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
      const revokedSerialInt = 123456;
      final revokedSerialBig =
          BigInt.parse('1234567890ABCDEF1234567890ABCDEF', radix: 16);
      final revokedSerialHex = '0xA1B2C3D4E5F60718293A4B5C6D7E8F90';

      final crl = openSsl.newCrlBuilder()
        ..setIssuerFromCertificate(issuerCert)
        ..setUpdateTimes(
          thisUpdate: now,
          nextUpdate: now.add(const Duration(hours: 24)),
        )
        ..addRevokedSerial(
          serialNumber: revokedSerialInt,
          revocationTime: now,
        )
        ..addRevokedSerialBigInt(
          serialNumber: revokedSerialBig,
          revocationTime: now,
        )
        ..addRevokedSerialHex(
          serialHex: revokedSerialHex,
          revocationTime: now,
        );
      final signed = crl.sign(issuerKey: caKey, hashAlgorithm: 'SHA256');

      final der = signed.toDer();
      final pem = signed.toPem();

      final parsedDer = openSsl.loadCrlDer(der);
      expect(parsedDer.isSerialRevoked(revokedSerialInt), isTrue);
      expect(parsedDer.isSerialRevokedBigInt(revokedSerialBig), isTrue);
      expect(parsedDer.isSerialRevokedHex(revokedSerialHex), isTrue);
      expect(parsedDer.isSerialRevoked(999999), isFalse);

      final parsedPem = openSsl.loadCrlPem(pem);
      expect(
        parsedPem.isSerialRevokedDecimal(revokedSerialInt.toString()),
        isTrue,
      );
    });

    test('Should read OCSP and CRL URLs from certificate extensions', () {
      final key = openSsl.generateRsa(2048);
      const ocspUrl = 'https://example.test/ocsp';
      const crlUrl = 'https://example.test/crl';

      final cert = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Leaf', organization: 'Test')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: false, critical: true)
        ..addOcspUrls(const [ocspUrl])
        ..addCrlDistributionPoints(const [crlUrl]);

      final signed = cert.sign(key, hashAlgorithm: 'SHA256');
      expect(signed.ocspUrls, contains(ocspUrl));
      expect(signed.crlDistributionPointUrls, contains(crlUrl));
    });
  });
}

Uint8List _buildOcspRequest(
    OpenSSL openSsl, Pointer<X509> subject, Pointer<X509> issuer,
    {bool includeNonce = false}) {
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

    if (includeNonce) {
      const nonceLength = 16;
      final nonce = calloc<UnsignedChar>(nonceLength);
      try {
        if (bindings.RAND_bytes(nonce, nonceLength) != 1) {
          throw StateError('Failed to generate nonce');
        }
        if (bindings.OCSP_request_add1_nonce(request, nonce, nonceLength) !=
            1) {
          throw StateError('Failed to add nonce to OCSP request');
        }
      } finally {
        calloc.free(nonce);
      }
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
