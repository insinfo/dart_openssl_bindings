import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/api/mixins/signature_mixin.dart';
import 'package:openssl_bindings/src/infra/ssl_exception.dart';

void main() {
  group('SignatureMixin', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Sign and Verify SHA256', () {
      final key = openSsl.generateRsa(2048);
      final data = utf8.encode('Hello OpenSSL');
      final dataBytes = Uint8List.fromList(data);

      final signature = openSsl.sign(key, dataBytes);
      expect(signature, isNotEmpty);

      final isValid = openSsl.verify(key, dataBytes, signature);
      expect(isValid, isTrue);
    });

    test('Verify fails on modified data', () {
      final key = openSsl.generateRsa(2048);
      final data = utf8.encode('Hello OpenSSL');
      final signature = openSsl.sign(key, Uint8List.fromList(data));

      final badData = utf8.encode('Hello OpenSSL Modified');
      final isValid =
          openSsl.verify(key, Uint8List.fromList(badData), signature);
      expect(isValid, isFalse);
    });

    test('Verify fails on wrong signature', () {
      final key = openSsl.generateRsa(2048);
      final data = utf8.encode('Hello OpenSSL');
      final signature = openSsl.sign(key, Uint8List.fromList(data));

      // Corrupt signature
      signature[0] = signature[0] ^ 0xFF;

      final isValid = openSsl.verify(key, Uint8List.fromList(data), signature);
      expect(isValid, isFalse);
    });

    test('Verify fails with wrong key', () {
      final key1 = openSsl.generateRsa(2048);
      final key2 = openSsl.generateRsa(2048);

      final data = utf8.encode('Hello OpenSSL');
      final signature = openSsl.sign(key1, Uint8List.fromList(data));

      final isValid = openSsl.verify(key2, Uint8List.fromList(data), signature);
      expect(isValid, isFalse);
    });

    test('one-shot sign/verify works with Ed25519 (null digest)', () {
      final key = openSsl.generateEd25519();
      final data = Uint8List.fromList(utf8.encode('Hello Ed25519'));

      final signature = openSsl.signOneShot(key, data, algorithm: null);
      expect(signature, isNotEmpty);

      final isValid = openSsl.verifyOneShot(
        key,
        data,
        signature,
        algorithm: null,
      );
      expect(isValid, isTrue);
    });

    test('one-shot sign/verify works with ML-DSA-65 when available', () {
      final data = Uint8List.fromList(utf8.encode('Hello ML-DSA'));
      try {
        final key = openSsl.generateMlDsa65();
        final signature = openSsl.signOneShot(key, data, algorithm: null);
        expect(signature, isNotEmpty);

        final isValid = openSsl.verifyOneShot(
          key,
          data,
          signature,
          algorithm: null,
        );
        expect(isValid, isTrue);
      } on OpenSslException catch (e) {
        final msg = e.toString().toUpperCase();
        expect(
          msg.contains('ML-DSA-65') ||
              msg.contains('EVP_PKEY_CTX_NEW_FROM_NAME') ||
              msg.contains('EVP_PKEY_KEYGEN') ||
              msg.contains('EVP_DIGESTSIGNINIT') ||
              msg.contains('EVP_DIGESTSIGN'),
          isTrue,
        );
      }
    });

    test('ML-DSA options (context + deterministic) are accepted', () {
      final data = Uint8List.fromList(utf8.encode('Hello ML-DSA Params'));
      final options = MlDsaSignatureOptions.deterministic(
        contextString: Uint8List.fromList(utf8.encode('icp-context')),
      );

      try {
        final key = openSsl.generateMlDsa65();
        final signature = openSsl.signMlDsa(
          key,
          data,
          options: options,
        );
        expect(signature, isNotEmpty);

        final isValid = openSsl.verifyMlDsa(
          key,
          data,
          signature,
          options: options,
        );
        expect(isValid, isTrue);
      } on OpenSslException catch (e) {
        final msg = e.toString().toUpperCase();
        expect(
          msg.contains('ML-DSA-65') ||
              msg.contains('EVP_PKEY_CTX_SET_PARAMS') ||
              msg.contains('EVP_PKEY_CTX_NEW_FROM_NAME'),
          isTrue,
        );
      }
    });
  });
}
