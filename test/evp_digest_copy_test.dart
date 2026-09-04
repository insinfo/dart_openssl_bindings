import 'dart:convert';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  late OpenSSL openSsl;

  setUp(() => openSsl = OpenSSL());

  String sha256Of(String text) =>
      openSsl.digestHex('sha256', Uint8List.fromList(utf8.encode(text)));

  group('EvpDigest.copy', () {
    test('forks the state: shared prefix, independent tails', () {
      final prefix = openSsl.startDigest('sha256');
      try {
        prefix.add(utf8.encode('Hello '));

        final a = prefix.copy();
        final b = prefix.copy();
        try {
          a.add(utf8.encode('World'));
          b.add(utf8.encode('Dart'));
          expect(a.finishHex(), sha256Of('Hello World'));
          expect(b.finishHex(), sha256Of('Hello Dart'));
        } finally {
          a.dispose();
          b.dispose();
        }

        // The original saw none of what its copies were fed.
        expect(prefix.length, 6);
        expect(prefix.finishHex(), sha256Of('Hello '));
      } finally {
        prefix.dispose();
      }
    });

    test('carries the algorithm, buffer size and byte count', () {
      final digest = openSsl.startDigest('sha512', bufferSize: 1024);
      try {
        digest.add(List.filled(3000, 7));

        final copy = digest.copy();
        try {
          expect(copy.algorithmName, 'sha512');
          expect(copy.bufferSize, 1024);
          expect(copy.length, 3000);
          expect(copy.isFinished, isFalse);
          expect(copy.isDisposed, isFalse);

          copy.add(List.filled(3000, 7));
          expect(copy.length, 6000);
          expect(
            copy.finish(),
            openSsl.digest('sha512', Uint8List.fromList(List.filled(6000, 7))),
          );
        } finally {
          copy.dispose();
        }
      } finally {
        digest.dispose();
      }
    });

    test('a copy outlives the digest it was taken from', () {
      final original = openSsl.startDigest('sha256')..add(utf8.encode('abc'));
      final copy = original.copy();
      original.dispose();
      try {
        expect(copy.finishHex(), sha256Of('abc'));
      } finally {
        copy.dispose();
      }
    });

    test('a finished or disposed digest cannot be copied', () {
      final finished = openSsl.startDigest('sha256')..finish();
      expect(finished.copy, throwsStateError);

      final disposed = openSsl.startDigest('sha256')..dispose();
      expect(disposed.copy, throwsStateError);
    });

    test('hashing a fixed header with many nonces, the motivating pattern', () {
      final header = openSsl.startDigest('sha256')
        ..add(utf8.encode('block-header:'));
      try {
        for (var nonce = 0; nonce < 50; nonce++) {
          final attempt = header.copy();
          try {
            attempt.add(utf8.encode('$nonce'));
            expect(attempt.finishHex(), sha256Of('block-header:$nonce'));
          } finally {
            attempt.dispose();
          }
        }
        expect(header.length, 13);
      } finally {
        header.dispose();
      }
    });
  });
}
