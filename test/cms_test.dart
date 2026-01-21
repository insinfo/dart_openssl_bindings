import 'dart:convert';
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
      // 1. Load Key and Cert (simplest way is to regenerate or use the ones from setup if we exposed them)
      // I'll regenerate fresh ones for isolation or use helpers if available.
      // But let's just reuse the logic to "load" from the PEM we saved, to test PEM loading too.
      final keyPem = File(keyPath).readAsStringSync();
      final certPem = File(certPath).readAsStringSync();

      final privateKey = openSsl.loadPrivateKeyPem(keyPem);
      // We don't have a PEM parser for X509 in our bindings yet (except X509Certificate from pointer). 
      // But we have `toPem`. We don't have `fromPem` in `X509Certificate` static?
      // Wait, `CmsPkcs7Signer` expects DER bytes for cert.
      // So we need to convert PEM to DER.
      // Basic PEM->DER for tests: strip header/footer and base64 decode.
      
      final certDer = _pemToDer(certPem);

      final signer = CmsPkcs7Signer(openSsl);
      
      final signatureDer = signer.signDetached(
        content: Uint8List.fromList('PDF-CONTENT-BYTES'.codeUnits),
        certificateDer: certDer,
        privateKey: privateKey,
      );

      expect(signatureDer, isNotEmpty);
      expect(signatureDer[0], equals(0x30)); // ASN.1 Sequence

      // Save for inspection if needed: File('sig.p7s').writeAsBytesSync(signatureDer);
    });
  });
}

Uint8List _pemToDer(String pem) {
  final lines = pem.split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty && !l.startsWith('-----'))
      .join('');
  return Uint8List.fromList(base64.decode(lines));
}
