import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  late OpenSSL openSsl;

  setUp(() => openSsl = OpenSSL());

  group('Argon2 known-answer tests', () {
    // RFC 9106, section 5: Argon2id, t=3, m=32 KiB, p=4, 32-byte tag, with
    // secret and associated data.
    final password = Uint8List.fromList(List.filled(32, 0x01));
    final salt = Uint8List.fromList(List.filled(16, 0x02));
    final secret = Uint8List.fromList(List.filled(8, 0x03));
    final associatedData = Uint8List.fromList(List.filled(12, 0x04));

    Argon2Options optionsFor(Argon2Type type) => Argon2Options(
          type: type,
          iterations: 3,
          memoryKib: 32,
          lanes: 4,
          length: 32,
          secret: secret,
          associatedData: associatedData,
        );

    test('Argon2id matches the RFC 9106 vector', () {
      final out = openSsl.argon2Derive(
        password,
        salt,
        options: optionsFor(Argon2Type.id),
        backend: Argon2Backend.dart,
      );
      expect(
        _hex(out),
        '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
      );
    });

    test('Argon2i matches the RFC 9106 vector', () {
      final out = openSsl.argon2Derive(
        password,
        salt,
        options: optionsFor(Argon2Type.i),
        backend: Argon2Backend.dart,
      );
      expect(
        _hex(out),
        'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
      );
    });

    test('Argon2d matches the RFC 9106 vector', () {
      final out = openSsl.argon2Derive(
        password,
        salt,
        options: optionsFor(Argon2Type.d),
        backend: Argon2Backend.dart,
      );
      expect(
        _hex(out),
        '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
      );
    });
  });

  group('Native and Dart backends agree', () {
    final password = Uint8List.fromList('correct horse battery'.codeUnits);
    final salt = Uint8List.fromList(List.generate(16, (i) => i * 7 & 0xff));

    test('same output for every variant (lanes = 1)', () {
      if (!openSsl.hasNativeArgon2) {
        markTestSkipped('libcrypto without native Argon2 (needs OpenSSL 3.2+)');
        return;
      }

      for (final type in Argon2Type.values) {
        final options = Argon2Options(
          type: type,
          iterations: 2,
          memoryKib: 256,
          lanes: 1,
          length: 32,
        );

        final native = openSsl.argon2Derive(password, salt,
            options: options, backend: Argon2Backend.native);
        final dart = openSsl.argon2Derive(password, salt,
            options: options, backend: Argon2Backend.dart);

        expect(_hex(native), _hex(dart), reason: type.phcName);
      }
    });

    test('secret and associated data are honoured by both', () {
      if (!openSsl.hasNativeArgon2) {
        markTestSkipped('libcrypto without native Argon2');
        return;
      }

      final options = Argon2Options(
        iterations: 2,
        memoryKib: 256,
        lanes: 1,
        length: 32,
        secret: Uint8List.fromList('pepper'.codeUnits),
        associatedData: Uint8List.fromList('ad'.codeUnits),
      );

      final native = openSsl.argon2Derive(password, salt,
          options: options, backend: Argon2Backend.native);
      final dart = openSsl.argon2Derive(password, salt,
          options: options, backend: Argon2Backend.dart);
      expect(_hex(native), _hex(dart));

      // Dropping the secret must change the result.
      final withoutSecret = openSsl.argon2Derive(
        password,
        salt,
        options: options.copyWith(secret: Uint8List(0)),
        backend: Argon2Backend.dart,
      );
      expect(_hex(withoutSecret), isNot(_hex(dart)));
    });
  });

  group('Password hashing (PHC strings)', () {
    test('hash and verify round trip', () {
      final phc = openSsl.argon2HashPassword(
        'the-user-password',
        options: Argon2Options.interactive,
      );

      expect(phc, startsWith(r'$argon2id$v=19$m=19456,t=2,p=1$'));
      expect(openSsl.argon2VerifyPassword(phc, 'the-user-password'), isTrue);
      expect(openSsl.argon2VerifyPassword(phc, 'the-wrong-password'), isFalse);
    });

    test('two hashes of the same password differ (random salt)', () {
      final a = openSsl.argon2HashPassword('x',
          options: Argon2Options.interactive);
      final b = openSsl.argon2HashPassword('x',
          options: Argon2Options.interactive);
      expect(a, isNot(b));
      expect(openSsl.argon2VerifyPassword(a, 'x'), isTrue);
      expect(openSsl.argon2VerifyPassword(b, 'x'), isTrue);
    });

    test('verification works across backends', () {
      if (!openSsl.hasNativeArgon2) {
        markTestSkipped('libcrypto without native Argon2');
        return;
      }

      // Hashed natively, verified in Dart: a hash written by a machine with
      // OpenSSL 3.2+ has to check out on one without it.
      final phc = openSsl.argon2HashPassword(
        'cross-backend',
        options: Argon2Options.interactive,
        backend: Argon2Backend.native,
      );
      expect(
        openSsl.argon2VerifyPassword(
          phc,
          'cross-backend',
          backend: Argon2Backend.dart,
        ),
        isTrue,
      );
    });

    test('a hash with a secret only verifies with the same secret', () {
      final secret = Uint8List.fromList('server-side-pepper'.codeUnits);
      final phc = openSsl.argon2HashPassword(
        'a-secret',
        options: Argon2Options.interactive.copyWith(secret: secret),
      );

      expect(openSsl.argon2VerifyPassword(phc, 'a-secret'), isFalse);
      expect(
        openSsl.argon2VerifyPassword(phc, 'a-secret', secret: secret),
        isTrue,
      );
    });

    test('malformed PHC strings are rejected, not thrown at', () {
      for (final bad in [
        '',
        'not-a-phc',
        r'$argon2id$v=19$m=1024,t=2$only-four-fields',
        r'$argon2xx$v=19$m=1024,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g',
        r'$argon2id$v=16$m=1024,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g',
        r'$argon2id$v=19$m=abc,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g',
      ]) {
        expect(openSsl.argon2VerifyPassword(bad, 'x'), isFalse, reason: bad);
        expect(tryParseArgon2Phc(bad), isNull, reason: bad);
      }
    });

    test('the PHC string round trips through the parser', () {
      final options = Argon2Options(
        iterations: 4,
        memoryKib: 8192,
        lanes: 1,
        length: 16,
      );
      final salt = openSsl.randomBytes(16);
      final phc = openSsl.argon2HashPassword('abc',
          options: options, salt: salt);

      final parsed = tryParseArgon2Phc(phc)!;
      expect(parsed.options.type, Argon2Type.id);
      expect(parsed.options.iterations, 4);
      expect(parsed.options.memoryKib, 8192);
      expect(parsed.options.lanes, 1);
      expect(parsed.options.length, 16);
      expect(parsed.salt, salt);
    });
  });

  group('Validation', () {
    test('rejects a short salt', () {
      expect(
        () => openSsl.argon2Derive(
          Uint8List.fromList('x'.codeUnits),
          Uint8List(4),
        ),
        throwsArgumentError,
      );
    });

    test('rejects an output shorter than 4 bytes', () {
      expect(
        () => openSsl.argon2Derive(
          Uint8List.fromList('x'.codeUnits),
          Uint8List(16),
          options: const Argon2Options(length: 2),
        ),
        throwsArgumentError,
      );
    });

    test('rejects memory below 8 * lanes', () {
      expect(
        () => openSsl.argon2Derive(
          Uint8List.fromList('x'.codeUnits),
          Uint8List(16),
          options: const Argon2Options(memoryKib: 8, lanes: 4),
        ),
        throwsArgumentError,
      );
    });
  });
}
