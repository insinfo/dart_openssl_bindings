import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/cms/cms_pkcs7_signer.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';
import 'package:test/test.dart';

void main() {
  group('CMS PKCS#7 Signer Tests', () {
    late OpenSSL openSsl;
    late Directory tempDir;
    late String certPath;
    late String keyPath;

    setUpAll(() async {
      openSsl = OpenSSL();
      tempDir = await Directory.systemTemp.createTemp('openssl_cms_tests_');
      certPath = '${tempDir.path}/signer.crt';
      keyPath = '${tempDir.path}/signer.key';

      // 1. Generate Key
      final pkey = openSsl.generateRsa(2048);

      // 2. Generate Self-Signed Cert
      final builder = X509CertificateBuilder(openSsl);
      builder.setSubject(
        commonName: 'PDF Signer',
        organization: 'Test CMS',
        country: 'US',
      );
      builder.setIssuerAsSubject();
      builder.setValidity(notAfterOffset: 3600);
      builder.setPublicKey(pkey);
      
      // Sign returns the cert wrapper
      final cert = builder.sign(pkey);

      // 3. Save to disk (optional, mostly for debugging or reloading)
      await File(keyPath).writeAsString(pkey.toPrivateKeyPem());
      await File(certPath).writeAsString(cert.toPem());
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    test('Should generate valid detached signature structure', () {
      final keyPem = File(keyPath).readAsStringSync();
      final certPem = File(certPath).readAsStringSync();

      final privateKey = openSsl.loadPrivateKeyPem(keyPem);
      final certDer = openSsl.convertCertificatePemToDer(certPem);

      final signer = CmsPkcs7Signer(openSsl);

      final signatureDer = signer.signDetached(
        content: Uint8List.fromList('PDF-CONTENT-BYTES'.codeUnits),
        certificateDer: certDer,
        privateKey: privateKey,
      );

      expect(signatureDer, isNotEmpty);
      expect(signatureDer[0], equals(0x30)); // ASN.1 Sequence
    });

    test('Should verify detached signature with trusted root', () {
      final rootKey = openSsl.generateRsa(2048);
      final rootBuilder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Test Root CA', organization: 'Test CMS')
        ..setIssuerAsSubject()
        ..setPublicKey(rootKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: true, critical: true)
        ..addKeyUsage(
          keyCertSign: true,
          cRLSign: true,
          critical: true,
        );
      final rootCert = rootBuilder.sign(rootKey);

      final leafKey = openSsl.generateRsa(2048);
      final leafBuilder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'Leaf Signer', organization: 'Test CMS')
        ..setIssuer(issuerCert: rootCert)
        ..setPublicKey(leafKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: false, critical: true)
        ..addKeyUsage(
          digitalSignature: true,
          keyEncipherment: true,
          critical: true,
        );
      final leafCert = leafBuilder.sign(rootKey);

      final content = Uint8List.fromList('SIGNED-CONTENT'.codeUnits);
      final signatureDer = openSsl.signDetached(
        content: content,
        certificate: leafCert,
        privateKey: leafKey,
        extraCertsDer: [openSsl.encodeCertificateDer(rootCert)],
        hashAlgorithm: 'SHA256',
      );

      final rootDer = openSsl.encodeCertificateDer(rootCert);
      final isValid = openSsl.verifyCmsDetached(
        cmsDer: signatureDer,
        content: content,
        trustedCertDer: rootDer,
      );

      expect(isValid, isTrue);
    });
  });
}
