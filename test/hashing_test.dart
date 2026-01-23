import 'dart:convert';
import 'dart:typed_data';
import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Hashing and HMAC', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Digest SHA-256', () {
      final input = utf8.encode('Hello World');
      final expected = 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e';
      
      final d = openSsl.digest('sha256', Uint8List.fromList(input));
      expect(toHex(d), equals(expected));
    });

    test('Digest SHA-512', () {
      final input = utf8.encode('Hello World');
      final expected = '2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b';
      
      final d = openSsl.digest('sha512', Uint8List.fromList(input));
      expect(toHex(d), equals(expected));
    });

    test('HMAC-SHA256', () {
      final key = utf8.encode('key');
      final data = utf8.encode('The quick brown fox jumps over the lazy dog');
      final expected = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8';
      
      final h = openSsl.hmac('sha256', Uint8List.fromList(key), Uint8List.fromList(data));
      expect(toHex(h), equals(expected));
    });
  });
}

String toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
