import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  group('X509 extensions builder', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('adds SAN otherName, CRL/OCSP URLs and policies', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl);

      builder.setSubject(
        commonName: 'Teste Ext',
        organization: 'OpenSSL Bindings',
        country: 'BR',
      );
      builder.setIssuerAsSubject();
      builder.setValidity(notAfterOffset: 3600);
      builder.setPublicKey(key);

      builder.addSubjectAltNameOtherNames([
        const X509OtherName('2.16.76.1.3.1', '0101200012345678901'),
      ]);
      builder.addCrlDistributionPoints([
        'http://example.com/crl.pem',
      ]);
      builder.addOcspUrls([
        'http://example.com/ocsp',
      ]);
      builder.addCertificatePolicies([
        '2.16.76.1.2.1.1',
      ]);

      final cert = builder.sign(key);
      final pem = cert.toPem();

      expect(pem, contains('BEGIN CERTIFICATE'));
      expect(cert.icpBrasilInfo.policyOids, contains('2.16.76.1.2.1.1'));
      expect(cert.certificatePolicyOids, contains('2.16.76.1.2.1.1'));
      expect(
        cert.subjectAltNameOtherNames['2.16.76.1.3.1'],
        equals('0101200012345678901'),
      );
    });

    test('writes and reads back SAN dNSName, e-mail, IP and URI', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'server.example.test', organization: 'Test')
        ..setIssuerAsSubject()
        ..setValidity(notAfterOffset: 3600)
        ..setPublicKey(key)
        ..addSubjectAltNames(
          dnsNames: const ['server.example.test', 'www.example.test'],
          emailAddresses: const ['admin@example.test'],
          ipAddresses: const ['192.0.2.10', '2001:db8::1'],
          uris: const ['https://example.test/id'],
        );

      final cert = openSsl.loadCertificatePem(builder.sign(key).toPem());

      expect(
        cert.dnsNames,
        equals(['server.example.test', 'www.example.test']),
      );
      expect(cert.emailAddresses, equals(['admin@example.test']));
      expect(cert.ipAddresses, equals(['192.0.2.10', '2001:db8::1']));
      expect(cert.subjectAltNameUris, equals(['https://example.test/id']));
      expect(cert.subjectAltNameOtherNames, isEmpty);
    });

    test('reports empty SAN lists for a certificate without the extension', () {
      final key = openSsl.generateRsa(2048);
      final cert = (X509CertificateBuilder(openSsl)
            ..setSubject(commonName: 'No SAN')
            ..setIssuerAsSubject()
            ..setValidity(notAfterOffset: 3600)
            ..setPublicKey(key))
          .sign(key);

      expect(cert.dnsNames, isEmpty);
      expect(cert.emailAddresses, isEmpty);
      expect(cert.ipAddresses, isEmpty);
      expect(cert.subjectAltNameUris, isEmpty);
      expect(cert.certificatePolicyOids, isEmpty);
    });

    test('rejects a SAN value that would be split by the comma syntax', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Comma')
        ..setIssuerAsSubject()
        ..setValidity(notAfterOffset: 3600)
        ..setPublicKey(key);

      expect(
        () => builder.addSubjectAltNames(
          dnsNames: const ['a.example.test,b.example.test'],
        ),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => builder.addSubjectAltNames(emailAddresses: const ['  ']),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
