import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';



void main() {
  late OpenSSL openssl;

  setUpAll(() {
    openssl = OpenSSL();
  });

  group('X509CertificateBuilder (New)', () {
    test('generates self-signed certificate PEM', () {
      final builder = X509CertificateBuilder(openssl);
      builder.setSubject(commonName: 'Test Self Signed', organization: 'Dart OpenSSL');
      builder.setIssuerAsSubject(); // Subject = Issuer

      final key = openssl.generateRsa(2048);
      builder.setPublicKey(key);

      final cert = builder.sign(key);
      final pem = cert.toPem();
      final keyPem = key.toPrivateKeyPem();
      
      expect(pem, contains('BEGIN CERTIFICATE'));
      expect(keyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('adds key usage, extended key usage and policies', () {
      final key = openssl.generateRsa(2048);
      final builder = X509CertificateBuilder(openssl)
        ..setSubject(commonName: 'Usage Test', organization: 'Dart OpenSSL')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600)
        ..addKeyUsage(
          digitalSignature: true,
          keyEncipherment: true,
          keyCertSign: true,
          cRLSign: true,
          critical: true,
        )
        ..addExtendedKeyUsage(
          ['serverAuth', 'clientAuth'],
          critical: false,
        )
        ..addSubjectAltNameOtherNames(
          const [X509OtherName('2.16.76.1.3.1', '12345678901')],
        )
        ..addCertificatePolicies(
          const ['2.16.76.1.2.1.1'],
        );

      final cert = builder.sign(key);
      final info = cert.icpBrasilInfo;

      expect(info.otherNames['2.16.76.1.3.1'], equals('12345678901'));
      expect(info.policyOids, contains('2.16.76.1.2.1.1'));
    });

    test('supports BigInt serial numbers', () {
      final key = openssl.generateRsa(2048);
      final serial = openssl.generateSerialNumberBigInt(bytes: 16);

      final builder = X509CertificateBuilder(openssl)
        ..setSerialNumberBigInt(serial)
        ..setSubject(commonName: 'BigInt Serial', organization: 'Dart OpenSSL')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600);

      final cert = builder.sign(key);
      expect(cert.serialNumber, equals(serial.toString()));
    });

    test('sets validity from ASN1 time strings', () {
      final key = openssl.generateRsa(2048);
      final builder = X509CertificateBuilder(openssl)
        ..setSubject(commonName: 'Validity Strings', organization: 'Dart OpenSSL')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidityFromStrings(
          notBefore: '20260127000000Z',
          notAfter: '20270127000000Z',
        );

      final cert = builder.sign(key);
      expect(cert.notBefore, equals(DateTime.utc(2026, 1, 27)));
      expect(cert.notAfter, equals(DateTime.utc(2027, 1, 27)));
    });

    test('supports adj-based validity setters', () {
      final key = openssl.generateRsa(2048);
      final builder = X509CertificateBuilder(openssl)
        ..setSubject(commonName: 'Validity Adj', organization: 'Dart OpenSSL')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidityAdjEx(notAfterDays: 1)
        ..setValidityAdjFromEpoch(
          baseTime: DateTime.utc(2026, 1, 27),
          notBeforeDays: 0,
          notAfterDays: 2,
        );

      final cert = builder.sign(key);
      final nb = cert.notBefore;
      final na = cert.notAfter;
      expect(nb, isNotNull);
      expect(na, isNotNull);
      expect(na!.isAfter(nb!), isTrue);
    });
  });
}
