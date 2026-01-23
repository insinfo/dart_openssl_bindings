import 'dart:io';

import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_request_builder.dart';

void main() {
  group('Novas Funcionalidades (CSR, Key Enc, Validation)', () {
    late OpenSSL openSsl;
    late Directory tempDir;

    setUpAll(() async {
      openSsl = OpenSSL();
      tempDir = await Directory.systemTemp.createTemp('openssl_expansions_');
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    test('Deve gerar CSR (Certificate Signing Request)', () {
      final pkey = openSsl.generateRsa(2048);
      final builder = X509RequestBuilder(openSsl);
      
      builder.setSubject(
        commonName: 'Requester',
        organization: 'My Company',
        country: 'BR'
      );
      
      builder.setPublicKey(pkey);
      
      final csr = builder.sign(pkey);
      final pem = csr.toPem();
      
      expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
      expect(pem, contains('-----END CERTIFICATE REQUEST-----'));
    });

    test('Deve exportar chave privada encriptada (AES-256-CBC)', () {
      final pkey = openSsl.generateRsa(2048);
      final password = 'mysecretpassword';
      
      final pem = pkey.toPrivateKeyPem(password: password);
      
      expect(pem, contains('ENCRYPTED PRIVATE KEY')); 
      // Or 'BEGIN RSA PRIVATE KEY' with 'Proc-Type: 4,ENCRYPTED' header if using legacy format.
      // PEM_write_bio_PrivateKey usually writes PKCS#8 encrypted if newer OpenSSL, or traditional.
      // Let's inspect content.
      
      // Try to load it back
      final loadedKey = openSsl.loadPrivateKeyPem(pem, password: password);
      expect(loadedKey.handle, isNot(0));
      
      // Try to load with wrong password
      expect(
        () => openSsl.loadPrivateKeyPem(pem, password: 'wrong'),
        throwsException // OpenSslException
      );
    });
  });
}
