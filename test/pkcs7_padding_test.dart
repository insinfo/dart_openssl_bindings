import 'dart:typed_data';
import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('PKCS#7 padding', () {
    test('pad/unpad roundtrip', () {
      final openssl = OpenSSL();
      final data = Uint8List.fromList(List<int>.generate(37, (i) => i));

      final padded = openssl.pkcs7Pad(data, blockSize: 16);
      expect(padded.length % 16, 0);

      final unpadded = openssl.pkcs7Unpad(padded, blockSize: 16);
      expect(unpadded, data);
    });

    test('pad empty input', () {
      final openssl = OpenSSL();
      final data = Uint8List(0);
      final padded = openssl.pkcs7Pad(data, blockSize: 16);
      expect(padded.length, 16);
      expect(padded.every((b) => b == 16), isTrue);
      final unpadded = openssl.pkcs7Unpad(padded, blockSize: 16);
      expect(unpadded, data);
    });

    test('invalid padding throws', () {
      final openssl = OpenSSL();
      final invalid = Uint8List.fromList(List<int>.filled(16, 0x01));
      invalid[15] = 0x02;

      expect(
        () => openssl.pkcs7Unpad(invalid, blockSize: 16),
        throwsArgumentError,
      );
    });
  });

  group('AES-CBC PKCS#7 helper', () {
    test('encrypt/decrypt AES-256', () {
      final openssl = OpenSSL();
      final data = Uint8List.fromList(List<int>.generate(50, (i) => i + 1));
      final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final iv = Uint8List.fromList(List<int>.generate(16, (i) => 16 - i));

      final cipher = openssl.aesCbcPkcs7Encrypt(data: data, key: key, iv: iv);
      final plain = openssl.aesCbcPkcs7Decrypt(ciphertext: cipher, key: key, iv: iv);

      expect(plain, data);
    });
  });
}
