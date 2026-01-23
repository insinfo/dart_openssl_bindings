import 'dart:typed_data';
import 'dart:ffi';
import 'dart:convert';
import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  late OpenSSL openSsl;

  setUpAll(() {
    openSsl = OpenSSL();
  });

  group('ECDSA (Elliptic Curve Digital Signature Algorithm)', () {
    test('Sign and Verify using secp256r1 (prime256v1)', () {
      // 1. Generate EC Key
      final key = openSsl.generateEc('prime256v1');
      expect(key.handle, isNot(nullptr));

      // 2. Data
      final data = utf8.encode('Message to sign with ECDSA');
      final dataBytes = Uint8List.fromList(data);

      // 3. Sign
      // Default algorithm is SHA256 which is good for P-256
      final signature = openSsl.sign(key, dataBytes, algorithm: 'SHA256');
      expect(signature, isNotEmpty);

      // 4. Verify
      final isValid = openSsl.verify(key, dataBytes, signature, algorithm: 'SHA256');
      expect(isValid, isTrue);
    });

    test('Verification fails for modified message', () {
      final key = openSsl.generateEc('prime256v1');
      final data = Uint8List.fromList(utf8.encode('Original Message'));
      final signature = openSsl.sign(key, data);

      final modifiedData = Uint8List.fromList(utf8.encode('Original MessageX'));
      final isValid = openSsl.verify(key, modifiedData, signature);
      expect(isValid, isFalse);
    });

    test('Verification fails for wrong key', () {
      final aliceKey = openSsl.generateEc('prime256v1');
      final bobKey = openSsl.generateEc('prime256v1');
      
      final data = Uint8List.fromList(utf8.encode('Message'));
      final signature = openSsl.sign(aliceKey, data);
      
      final isValid = openSsl.verify(bobKey, data, signature);
      expect(isValid, isFalse);
    });
  });
}
