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
  });
}
