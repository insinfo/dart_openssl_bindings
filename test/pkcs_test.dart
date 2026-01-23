import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  group('PKCS helpers', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Extract certificates from PKCS#7/CMS (DER)', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'PKCS7 Signer', organization: 'Test Org')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600);

      final cert = builder.sign(key);
      final content = Uint8List.fromList('conteudo'.codeUnits);

      final cms = openSsl.signDetachedContentInfo(
        content: content,
        certificate: cert,
        privateKey: key,
      );

      final der = openSsl.encodeCms(cms);
      final certs = openSsl.loadCertificatesFromPkcs7Der(der);

      expect(certs, isNotEmpty);
      expect(certs.first.subject, contains('CN=PKCS7 Signer'));
    });

    test('Create and parse PKCS#12/PFX', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'PFX Holder', organization: 'Test Org')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600);

      final cert = builder.sign(key);

      final caKey = openSsl.generateRsa(2048);
      final caCert = (X509CertificateBuilder(openSsl)
            ..setSubject(commonName: 'Test CA')
            ..setIssuerAsSubject()
            ..setPublicKey(caKey)
            ..setValidity(notAfterOffset: 3600))
          .sign(caKey);

      final pfx = openSsl.createPkcs12(
        privateKey: key,
        certificate: cert,
        caCertificates: [caCert],
        password: 'secret',
        friendlyName: 'test-pfx',
      );

      final parsed = openSsl.parsePkcs12(pfx, password: 'secret');
      expect(parsed.certificate.subject, contains('CN=PFX Holder'));
      expect(parsed.caCertificates, isNotEmpty);

      final data = Uint8List.fromList('assinatura'.codeUnits);
      final sig = openSsl.sign(parsed.privateKey, data);
      expect(openSsl.verify(key, data, sig), isTrue);
    });
  });
}
