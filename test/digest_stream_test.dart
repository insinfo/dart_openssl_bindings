import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('Incremental digest', () {
    late OpenSSL openSsl;
    late Directory tempDir;

    setUp(() {
      openSsl = OpenSSL();
      tempDir = Directory.systemTemp.createTempSync('openssl_digest_test');
    });

    tearDown(() {
      if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
    });

    // 'Hello World' hashed with SHA-256, the same vector hashing_test.dart uses
    // for the one-shot path.
    const helloWorldSha256 =
        'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e';

    test('matches the one-shot digest when fed in one piece', () {
      final digest = openSsl.startDigest('sha256');
      try {
        digest.add(utf8.encode('Hello World'));
        expect(_hex(digest.finish()), equals(helloWorldSha256));
      } finally {
        digest.dispose();
      }
    });

    test('matches the one-shot digest when fed in several pieces', () {
      final digest = openSsl.startDigest('sha256');
      try {
        digest.add(utf8.encode('Hello'));
        digest.add(const <int>[]);
        digest.add(utf8.encode(' '));
        digest.add(utf8.encode('World'));
        expect(_hex(digest.finish()), equals(helloWorldSha256));
        expect(digest.length, equals(11));
      } finally {
        digest.dispose();
      }
    });

    test('splits chunks larger than the scratch buffer', () {
      // A buffer far smaller than the input forces the slicing path in `add`;
      // the digest must not depend on how the input was cut up.
      final data = Uint8List.fromList(
        List<int>.generate(300 * 1024, (i) => i % 256),
      );
      final expected = _hex(openSsl.digest('sha256', data));

      final digest = openSsl.startDigest('sha256', bufferSize: 1024);
      try {
        digest.add(data);
        expect(_hex(digest.finish()), equals(expected));
        expect(digest.length, equals(data.length));
      } finally {
        digest.dispose();
      }
    });

    test('digestStream matches the one-shot digest', () async {
      final chunks = <List<int>>[
        utf8.encode('Hello'),
        utf8.encode(' '),
        utf8.encode('World'),
      ];
      final result =
          await openSsl.digestStream('sha256', Stream.fromIterable(chunks));
      expect(_hex(result), equals(helloWorldSha256));
    });

    test('digestFile matches the one-shot digest over the same bytes',
        () async {
      final data = Uint8List.fromList(
        List<int>.generate(500 * 1024, (i) => (i * 7) % 256),
      );
      final file = File('${tempDir.path}/payload.bin')..writeAsBytesSync(data);

      final streamed = await openSsl.digestFile('sha256', file);
      expect(_hex(streamed), equals(_hex(openSsl.digest('sha256', data))));
    });

    test('digests an empty file', () async {
      final file = File('${tempDir.path}/empty.bin')..writeAsBytesSync([]);
      final result = await openSsl.digestFile('sha256', file);
      expect(
        _hex(result),
        equals(
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ),
      );
    });

    test('digestHex and finishHex agree with the byte-level result', () {
      final data = Uint8List.fromList(utf8.encode('Hello World'));
      expect(openSsl.digestHex('sha256', data), equals(helloWorldSha256));

      final digest = openSsl.startDigest('sha256');
      try {
        digest.add(data);
        expect(digest.finishHex(), equals(helloWorldSha256));
      } finally {
        digest.dispose();
      }
    });

    test('md5 is reachable by name, for legacy checksums', () {
      // OpenSSL 3 keeps MD5 in the default provider, so no provider juggling.
      expect(
        openSsl.digestHex('md5', Uint8List.fromList(utf8.encode('Hello World'))),
        equals('b10a8db164e0754105b7a99be72e3fe5'),
      );
    });

    test('supports other algorithms', () {
      final digest = openSsl.startDigest('sha512');
      try {
        digest.add(utf8.encode('Hello World'));
        expect(
          _hex(digest.finish()),
          equals(_hex(openSsl.digest(
            'sha512',
            Uint8List.fromList(utf8.encode('Hello World')),
          ))),
        );
      } finally {
        digest.dispose();
      }
    });

    test('rejects an unknown algorithm', () {
      expect(
        () => openSsl.startDigest('not-a-digest'),
        throwsA(isA<OpenSslException>()),
      );
    });

    test('rejects a non-positive buffer size', () {
      expect(
        () => openSsl.startDigest('sha256', bufferSize: 0),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('refuses to be used after finish', () {
      final digest = openSsl.startDigest('sha256');
      try {
        digest.finish();
        expect(digest.isFinished, isTrue);
        expect(() => digest.finish(), throwsStateError);
        expect(() => digest.add(utf8.encode('x')), throwsStateError);
      } finally {
        digest.dispose();
      }
    });

    test('finish releases the context and dispose stays idempotent', () {
      final digest = openSsl.startDigest('sha256');
      digest.add(utf8.encode('Hello World'));
      digest.finish();
      expect(digest.isDisposed, isTrue);
      // A double free would crash the VM rather than fail the expectation.
      digest.dispose();
      digest.dispose();
    });

    test('refuses to be used after dispose', () {
      final digest = openSsl.startDigest('sha256');
      digest.dispose();
      expect(() => digest.add(utf8.encode('x')), throwsStateError);
      expect(() => digest.finish(), throwsStateError);
    });

    test('a failing stream leaves the digest disposable', () async {
      final digest = openSsl.startDigest('sha256');
      final broken = Stream<List<int>>.fromIterable([utf8.encode('Hello')])
          .asyncExpand((chunk) => Stream<List<int>>.error(StateError('boom')));
      try {
        await expectLater(digest.addStream(broken), throwsStateError);
      } finally {
        digest.dispose();
      }
      expect(digest.isDisposed, isTrue);
    });

    test('digestStream propagates a stream failure', () {
      expect(
        openSsl.digestStream(
          'sha256',
          Stream<List<int>>.error(StateError('boom')),
        ),
        throwsStateError,
      );
    });

    test('many digests in sequence do not exhaust native memory', () {
      // Guards the release path: a leaked EVP_MD_CTX per call would show up
      // here long before it did in production.
      for (var i = 0; i < 2000; i++) {
        final digest = openSsl.startDigest('sha256');
        try {
          digest.add(utf8.encode('iteration $i'));
          digest.finish();
        } finally {
          digest.dispose();
        }
      }
    });
  });
}
