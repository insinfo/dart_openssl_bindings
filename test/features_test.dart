import 'package:openssl_bindings/openssl.dart';

import 'package:test/test.dart';

void main() {
  group('Encrypted Key and Certificate Details Test', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Should parse X509 Certificate details (Subject, Issuer, Serial)', () {
      final pkey = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();

      builder.setSubject(commonName: 'Test Cert', organization: 'OpenSSL Dart');
      builder.setIssuerAsSubject();
      builder.setPublicKey(pkey);

      final cert = builder.sign(pkey);

      expect(cert, isNotNull);
      // Validating Subject string format involves OpenSSL specific formatting
      // Usually "CN=Test Cert,O=OpenSSL Dart" or similar depending on configuration.
      // But we just check if it contains our values.
      final subject = cert.subject;
      print('Subject: $subject');
      expect(subject, contains('Test Cert'));
      expect(subject, contains('OpenSSL Dart'));

      final issuer = cert.issuer;
      expect(
          issuer, equals(subject)); // Since self-signed and setIssuerAsSubject

      final serial = cert.serialNumber;
      print('Serial: $serial');
      expect(serial, equals('1')); // Default builder serial is 1

      expect(cert.version, equals(3));
    });
  });
}
