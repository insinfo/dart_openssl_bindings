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
    });
  });
}
