import 'dart:typed_data';

import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Cipher algorithms', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('AES-128-GCM round trip', () {
      final key = Uint8List.fromList(List<int>.generate(16, (i) => i));
      final iv = Uint8List.fromList(List<int>.generate(12, (i) => i + 1));
      final data = Uint8List.fromList('hello-gcm'.codeUnits);

      final enc = openSsl.aes128GcmEncrypt(data: data, key: key, iv: iv);
      final dec = openSsl.aes128GcmDecrypt(
        ciphertext: enc['ciphertext']!,
        key: key,
        iv: iv,
        tag: enc['tag']!,
      );

      expect(dec, equals(data));
    });

    test('AES-128-CBC round trip', () {
      final key = Uint8List.fromList(List<int>.generate(16, (i) => 0xA0 + i));
      final iv = Uint8List.fromList(List<int>.generate(16, (i) => 0x0F - i));
      final data = Uint8List.fromList('hello-cbc-128'.codeUnits);

      final enc = openSsl.aes128CbcEncrypt(data: data, key: key, iv: iv);
      final dec = openSsl.aes128CbcDecrypt(ciphertext: enc, key: key, iv: iv);

      expect(dec, equals(data));
    });

    test('Rijndael-128-CBC alias round trip', () {
      final key = Uint8List.fromList(List<int>.generate(16, (i) => 0x11 + i));
      final iv = Uint8List.fromList(List<int>.generate(16, (i) => 0x22 + i));
      final data = Uint8List.fromList('rijndael-128'.codeUnits);

      final enc = openSsl.rijndael128CbcEncrypt(data: data, key: key, iv: iv);
      final dec = openSsl.rijndael128CbcDecrypt(ciphertext: enc, key: key, iv: iv);

      expect(dec, equals(data));
    });

    test('ChaCha20-Poly1305 round trip', () {
      final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final iv = Uint8List.fromList(List<int>.generate(12, (i) => 0x55 + i));
      final data = Uint8List.fromList('hello-chacha-aead'.codeUnits);

      final enc = openSsl.chacha20Poly1305Encrypt(data: data, key: key, iv: iv);
      final dec = openSsl.chacha20Poly1305Decrypt(
        ciphertext: enc['ciphertext']!,
        key: key,
        iv: iv,
        tag: enc['tag']!,
      );

      expect(dec, equals(data));
    });

    test('ChaCha20 round trip', () {
      final key = Uint8List.fromList(List<int>.generate(32, (i) => 0x33 + i));
      final iv = Uint8List.fromList(List<int>.generate(16, (i) => 0x44 + i));
      final data = Uint8List.fromList('hello-chacha'.codeUnits);

      final enc = openSsl.chacha20Encrypt(data: data, key: key, iv: iv);
      final dec = openSsl.chacha20Decrypt(ciphertext: enc, key: key, iv: iv);

      expect(dec, equals(data));
    });
  });
}