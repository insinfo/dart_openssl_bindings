import 'package:test/test.dart';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_request_builder.dart';

void main() {
  late OpenSSL openssl;

  setUpAll(() {
    openssl = OpenSSL();
  });

  test('Should create a valid CSR', () {
    // 1. Generate KeyPair
    final pkey = openssl.generateRsa(2048);
    expect(pkey.handle, isNot(nullptr));

    // 2. Build CSR
    final builder = X509RequestBuilder(openssl);
    builder.setSubject(
      commonName: 'Test User',
      country: 'US',
      organization: 'Test Corp'
    );
    builder.setPublicKey(pkey);
    final csr = builder.sign(pkey);
    
    expect(csr.handle, isNot(nullptr));

    // 4. Export to PEM
    final pem = csr.toPem();

    expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
    expect(pem, contains('-----END CERTIFICATE REQUEST-----'));
  });

  test('Should load a CSR back and read subject, version and public key', () {
    final key = openssl.generateRsa(2048);
    final csr = (openssl.newCsrBuilder()
          ..setSubject(
            commonName: 'Loaded User',
            country: 'BR',
            organization: 'Test Corp',
          )
          ..setPublicKey(key))
        .sign(key);

    final pem = csr.toPem();
    final der = csr.toDer();
    expect(der, isNotEmpty);
    expect(der.first, equals(0x30)); // DER SEQUENCE

    for (final loaded in [
      openssl.loadCsrPem(pem),
      openssl.loadCsrDer(der),
      openssl.loadCsrBytes(der),
      openssl.loadCsrBytes(Uint8List.fromList(pem.codeUnits)),
    ]) {
      expect(loaded.version, equals(1));
      expect(loaded.subject, contains('Loaded User'));
      expect(loaded.subject, equals(csr.subject));

      // The CSR is self-signed: it proves the sender holds the private key.
      expect(loaded.verifySignature(), isTrue);

      final pub = loaded.publicKey;
      try {
        expect(pub.handle, isNot(nullptr));
      } finally {
        pub.dispose();
      }
      loaded.dispose();
    }
  });

  test('Should reject a CSR whose signature does not match the key', () {
    final key = openssl.generateRsa(2048);
    final otherKey = openssl.generateRsa(2048);

    final csr = (openssl.newCsrBuilder()
          ..setSubject(commonName: 'Mismatch')
          ..setPublicKey(key))
        .sign(key);

    final loaded = openssl.loadCsrPem(csr.toPem());
    expect(loaded.verifySignature(), isTrue);

    final wrongKey = openssl.loadPublicKeyPem(otherKey.toPublicKeyPem());
    try {
      expect(loaded.verifySignature(wrongKey), isFalse);
    } finally {
      wrongKey.dispose();
    }
  });
}
