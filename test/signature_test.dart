import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';

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
      final isValid = openSsl.verify(key, Uint8List.fromList(badData), signature);
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
  });
}
