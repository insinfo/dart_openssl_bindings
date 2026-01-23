import 'dart:convert';
import 'dart:typed_data';
import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('PBKDF2 HMAC-SHA256 Test', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    // Test Vectors from RFC 6070

    test('RFC 6070 Test Vector 1: c=1', () {
      final password = utf8.encode('password');
      final salt = utf8.encode('salt');
      final iterations = 1;
      final dkLen = 32;
      final expected = '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b';

      final derived = openSsl.pbkdf2(
        password: Uint8List.fromList(password), 
        salt: Uint8List.fromList(salt), 
        iterations: iterations, 
        keyLength: dkLen
      );

      expect(toHex(derived), equals(expected));
    });

    test('RFC 6070 Test Vector 2: c=2', () {
      final password = utf8.encode('password');
      final salt = utf8.encode('salt');
      final iterations = 2;
      final dkLen = 32;
      final expected = 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43';

      final derived = openSsl.pbkdf2(
        password: Uint8List.fromList(password), 
        salt: Uint8List.fromList(salt), 
        iterations: iterations, 
        keyLength: dkLen
      );

      expect(toHex(derived), equals(expected));
    });
    
    test('RFC 6070 Test Vector 3: c=4096', () {
        final password = utf8.encode('password');
        final salt = utf8.encode('salt');
        final iterations = 4096;
        final dkLen = 32;
        final expected = 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a';
        
        final derived = openSsl.pbkdf2(
            password: Uint8List.fromList(password), 
            salt: Uint8List.fromList(salt), 
            iterations: iterations, 
            keyLength: dkLen
        );
        
        expect(toHex(derived), equals(expected));
    });
  });
}

String toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
