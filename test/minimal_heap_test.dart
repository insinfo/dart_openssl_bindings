import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  group('Minimal heap test', () {
    late OpenSSL openSsl;

    setUpAll(() {
      openSsl = OpenSSL();
    });

    test('generateRsa only', () {
      final pkey = openSsl.generateRsa(2048);
      expect(pkey.handle, isNot(0));
    });

    test('builder with subject only', () {
      final pkey = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl);
      builder.setSubject(commonName: 'Test');
      builder.setPublicKey(pkey);
      builder.setIssuerAsSubject();
      final cert = builder.sign(pkey);
      expect(cert.subject, contains('CN=Test'));
    });

    test('builder with subject and issuer', () {
      final pkey = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl);
      builder.setSubject(
        commonName: 'Test Cert',
        organization: 'Test Org',
        country: 'BR',
      );
      builder.setIssuer(
        commonName: 'Test CA',
        organization: 'CA Org',
        country: 'US',
      );
      builder.setPublicKey(pkey);
      final cert = builder.sign(pkey);
      expect(cert.subject, contains('CN=Test Cert'));
      expect(cert.issuer, contains('CN=Test CA'));
    });
  });
}
