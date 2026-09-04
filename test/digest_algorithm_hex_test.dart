import 'dart:convert';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  late OpenSSL openSsl;

  setUp(() => openSsl = OpenSSL());

  final helloWorld = Uint8List.fromList(utf8.encode('Hello World'));
  // The same vector hashing_test.dart and digest_stream_test.dart use.
  const helloWorldSha256 =
      'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e';

  group('Hex helpers', () {
    test('encodeHex is lowercase, two digits per byte', () {
      expect(encodeHex(Uint8List.fromList([0, 1, 0x0a, 0xff, 0x7f])),
          '00010aff7f');
      expect(encodeHex(Uint8List(0)), '');
      expect(encodeHex(const <int>[0xab, 0xcd]), 'abcd');
    });

    test('decodeHex round-trips and accepts either case', () {
      final bytes = Uint8List.fromList(List.generate(256, (i) => i));
      expect(decodeHex(encodeHex(bytes)), bytes);
      expect(decodeHex('DEADbeef'), [0xde, 0xad, 0xbe, 0xef]);
      expect(decodeHex(''), isEmpty);
    });

    test('decodeHex rejects odd lengths and non-hex characters', () {
      expect(() => decodeHex('abc'), throwsFormatException);
      expect(() => decodeHex('zz'), throwsFormatException);
      expect(() => decodeHex('0x10'), throwsFormatException);
      expect(() => decodeHex('a b'), throwsFormatException);
    });
  });

  group('Hex digests', () {
    test('sha256Hex is sha256 through encodeHex', () {
      expect(openSsl.sha256Hex(helloWorld), helloWorldSha256);
      expect(
          openSsl.sha256Hex(helloWorld), encodeHex(openSsl.sha256(helloWorld)));
    });

    test('hmacHex is hmac through encodeHex', () {
      final key = Uint8List.fromList(utf8.encode('key'));
      final fox = Uint8List.fromList(
          utf8.encode('The quick brown fox jumps over the lazy dog'));

      // HMAC-SHA256 known answer for this key and message.
      expect(
        openSsl.hmacHex('sha256', key, fox),
        'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
      );
      expect(
        openSsl.hmacHex(DigestAlgorithm.sha256, key, helloWorld),
        encodeHex(openSsl.hmac('sha256', key, helloWorld)),
      );
    });
  });

  group('DigestAlgorithm', () {
    test('is the OpenSSL name underneath', () {
      expect(DigestAlgorithm.sha256, 'sha256');
      expect(DigestAlgorithm.sha256.opensslName, 'sha256');
      expect(DigestAlgorithm.sha3_256, 'sha3-256');
      expect(const DigestAlgorithm('whirlpool'), 'whirlpool');
    });

    test('takes the same path as the plain string', () {
      expect(openSsl.digestHex(DigestAlgorithm.sha256, helloWorld),
          helloWorldSha256);
      expect(openSsl.digestHex(DigestAlgorithm.sha256, helloWorld),
          openSsl.digestHex('sha256', helloWorld));
    });

    test('every constant is accepted by digest, hmac and startDigest', () {
      final key = Uint8List.fromList([1, 2, 3]);
      for (final algorithm in DigestAlgorithm.values) {
        final bytes = openSsl.digest(algorithm, helloWorld);
        expect(bytes, isNotEmpty, reason: algorithm);
        expect(openSsl.digestHex(algorithm, helloWorld), encodeHex(bytes),
            reason: algorithm);
        expect(openSsl.hmac(algorithm, key, helloWorld), isNotEmpty,
            reason: algorithm);

        final digest = openSsl.startDigest(algorithm);
        try {
          digest.add(helloWorld);
          expect(digest.finish(), bytes, reason: algorithm);
        } finally {
          digest.dispose();
        }
      }
    });

    test('an unknown name is still a runtime error, as before', () {
      expect(
        () =>
            openSsl.digest(const DigestAlgorithm('no-such-digest'), helloWorld),
        throwsA(isA<OpenSslException>()),
      );
    });
  });
}
