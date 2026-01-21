import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';

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
  });
}
