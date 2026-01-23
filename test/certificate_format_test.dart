import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

import 'certs.dart';

void main() {
  group('Certificate format conversion', () {
    late OpenSSL openssl;

    setUp(() {
      openssl = OpenSSL();
    });

    test('loads certificate bytes from PEM and DER', () {
      final certFromPem = openssl.loadCertificateBytes(
        Uint8List.fromList(rawPemCertificate.codeUnits),
      );
      final certFromDer = openssl.loadCertificateBytes(
        Uint8List.fromList(rawDerCertificate),
      );

      expect(certFromPem.subject, isNotEmpty);
      expect(certFromDer.subject, isNotEmpty);
    });

    test('converts PEM to DER and back', () {
      final der = openssl.convertCertificatePemToDer(rawPemCertificate);
      final pem = openssl.convertCertificateDerToPem(der);

      final certFromPem = openssl.loadCertificatePem(pem);
      expect(certFromPem.subject, contains('ISRG Root X1'));
    });

    test('encodes certificate to DER and PEM', () {
      final cert = openssl.loadCertificatePem(rawPemCertificate);
      final der = openssl.encodeCertificateDer(cert);
      final pem = openssl.encodeCertificatePem(cert);

      expect(der, isNotEmpty);
      expect(pem, contains('BEGIN CERTIFICATE'));
    });
  });
}
