import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';


void main() {
  group('Builder dispose safety', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('X509CertificateBuilder dispose prevents reuse', () {
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'Dispose Test');
      builder.dispose();

      expect(() => builder.setSerialNumber(2), throwsStateError);
    });

    test('X509CertificateBuilder dispose after sign is safe', () {
      final key = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'Dispose Test');
      builder.setIssuerAsSubject();
      builder.setPublicKey(key);

      final cert = builder.sign(key);
      expect(cert.subject, contains('Dispose Test'));

      expect(() => builder.dispose(), returnsNormally);
    });

    test('X509CertificateBuilder rejects reuse after sign', () {
      final key = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'Reuse Test');
      builder.setIssuerAsSubject();
      builder.setPublicKey(key);

      builder.sign(key);

      expect(() => builder.setSerialNumber(10), throwsStateError);
      expect(() => builder.sign(key), throwsStateError);
    });

    test('X509RequestBuilder dispose prevents reuse', () {
      final builder = X509RequestBuilder(openSsl);
      builder.setSubject(commonName: 'Dispose Test');
      builder.dispose();

      expect(() => builder.setPublicKey(openSsl.generateRsa(2048)), throwsStateError);
    });

    test('X509RequestBuilder rejects reuse after sign', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509RequestBuilder(openSsl);
      builder.setSubject(commonName: 'Reuse Test');
      builder.setPublicKey(key);

      builder.sign(key);

      expect(() => builder.setSubject(commonName: 'Again'), throwsStateError);
      expect(() => builder.sign(key), throwsStateError);
    });
  });
}
