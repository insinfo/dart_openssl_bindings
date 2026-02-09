import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/infra/ssl_exception.dart';

void main() {
  group('EvpPkey', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('generateRsa generates a valid key pair', () {
      final key = openSsl.generateRsa(2048);
      expect(key, isNotNull);

      final pem = key.toPrivateKeyPem();
      expect(pem, isNotNull);
      expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));
      expect(pem, endsWith('-----END PRIVATE KEY-----\n'));

      final pubPem = key.toPublicKeyPem();
      expect(pubPem, isNotNull);
      expect(pubPem, startsWith('-----BEGIN PUBLIC KEY-----'));

      // Memory should be freed by Finalizer eventually, but we can't test that easily here.
    });

    test('can load private key from PEM', () {
      final key = openSsl.generateRsa(2048);
      final pem = key.toPrivateKeyPem();

      final keyLoaded = openSsl.loadPrivateKeyPem(pem);
      expect(keyLoaded, isNotNull);

      final pem2 = keyLoaded.toPrivateKeyPem();
      expect(pem2, equals(pem));
    });

    test('can load public key from PEM', () {
      final key = openSsl.generateRsa(2048);
      final pubPem = key.toPublicKeyPem();

      final keyLoaded = openSsl.loadPublicKeyPem(pubPem);
      expect(keyLoaded, isNotNull);

      final pubPem2 = keyLoaded.toPublicKeyPem();
      expect(pubPem2, equals(pubPem));
    });

    test('generateEd25519 generates a valid key pair', () {
      final key = openSsl.generateEd25519();
      final pem = key.toPrivateKeyPem();
      expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));

      final pubPem = key.toPublicKeyPem();
      expect(pubPem, startsWith('-----BEGIN PUBLIC KEY-----'));
    });

    test('generateX25519 generates a valid key pair', () {
      final key = openSsl.generateX25519();
      final pem = key.toPrivateKeyPem();
      expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));

      final pubPem = key.toPublicKeyPem();
      expect(pubPem, startsWith('-----BEGIN PUBLIC KEY-----'));
    });

    test('generateMlDsa65 works when provider is available', () {
      try {
        final key = openSsl.generateMlDsa65();
        final pem = key.toPrivateKeyPem();
        expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));
      } on OpenSslException catch (e) {
        final msg = e.toString().toUpperCase();
        expect(
          msg.contains('ML-DSA-65') ||
              msg.contains('EVP_PKEY_CTX_NEW_FROM_NAME') ||
              msg.contains('EVP_PKEY_KEYGEN'),
          isTrue,
        );
      }
    });
  });
}
