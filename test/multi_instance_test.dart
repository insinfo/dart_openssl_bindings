import 'dart:convert';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Multi-instance isolation', () {
    test('independent instances can run in parallel', () async {
      Future<void> runInstance(int seed) async {
        final openssl = OpenSSL();

        // Hash + HMAC
        final data = Uint8List.fromList(utf8.encode('data-$seed'));
        final digest = openssl.digest('sha256', data);
        expect(digest, isNotEmpty);

        final mac = openssl.hmac('sha256', Uint8List.fromList([seed]), data);
        expect(mac, isNotEmpty);

        // AES-CBC
        final key = Uint8List(32)..[0] = seed;
        final iv = Uint8List(16)..[0] = seed;
        final cipher = openssl.aes256CbcEncrypt(data: data, key: key, iv: iv);
        final plain = openssl.aes256CbcDecrypt(ciphertext: cipher, key: key, iv: iv);
        expect(plain, equals(data));

        // RSA sign/verify
        final pkey = openssl.generateRsa(2048);
        final sig = openssl.sign(pkey, data);
        expect(openssl.verify(pkey, data, sig), isTrue);
      }

      await Future.wait([
        runInstance(1),
        runInstance(2),
        runInstance(3),
        runInstance(4),
      ]);
    });
  });
}
