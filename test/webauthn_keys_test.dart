import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

/// Covers what a WebAuthn/passkey verifier needs from this package: the two
/// passkey signature algorithms (ES256 and EdDSA) and loading a public key that
/// arrives as DER, which is what a COSE key becomes once re-encoded.
void main() {
  late OpenSSL openSsl;

  setUp(() => openSsl = OpenSSL());

  Uint8List derOfPublicKey(EvpPkey key) {
    final pem = key.toPublicKeyPem();
    final body = pem
        .split('\n')
        .where((line) => line.isNotEmpty && !line.startsWith('-----'))
        .join();
    return Uint8List.fromList(base64.decode(body));
  }

  final signedData =
      Uint8List.fromList('authenticatorData || clientDataHash'.codeUnits);

  group('keyRequiresOneShotSignature', () {
    test('is true for Ed25519 and Ed448', () {
      expect(
        openSsl.keyRequiresOneShotSignature(openSsl.generateEd25519()),
        isTrue,
      );
      expect(
        openSsl.keyRequiresOneShotSignature(openSsl.generateEd448()),
        isTrue,
      );
    });

    test('is false for RSA and EC', () {
      expect(
        openSsl.keyRequiresOneShotSignature(openSsl.generateRsa(2048)),
        isFalse,
      );
      expect(
        openSsl.keyRequiresOneShotSignature(openSsl.generateEc('prime256v1')),
        isFalse,
      );
    });
  });

  group('sign/verify with EdDSA', () {
    test('Ed25519 works through sign/verify, without one-shot boilerplate', () {
      // Ed25519 rejects an external digest; before the fallback this raised
      // `error:1C80007A:Provider routines::invalid digest`.
      final key = openSsl.generateEd25519();
      final signature = openSsl.sign(key, signedData);

      expect(signature, isNotEmpty);
      expect(openSsl.verify(key, signedData, signature), isTrue);
      expect(
        openSsl.verify(
          key,
          Uint8List.fromList('other data'.codeUnits),
          signature,
        ),
        isFalse,
      );
    });

    test('Ed448 works the same way', () {
      final key = openSsl.generateEd448();
      final signature = openSsl.sign(key, signedData);
      expect(openSsl.verify(key, signedData, signature), isTrue);
    });

    test('the fallback can be switched off', () {
      // Without the fallback OpenSSL is asked to hash first, which Ed25519
      // refuses — this is the raw error the fallback exists to avoid.
      final key = openSsl.generateEd25519();
      expect(
        () => openSsl.sign(key, signedData, allowOneShotFallback: false),
        throwsA(isA<Exception>()),
      );
    });

    test('ES256 and RS256 keep working through the digest path', () {
      final ec = openSsl.generateEc('prime256v1');
      expect(
        openSsl.verify(ec, signedData, openSsl.sign(ec, signedData)),
        isTrue,
      );

      final rsa = openSsl.generateRsa(2048);
      expect(
        openSsl.verify(rsa, signedData, openSsl.sign(rsa, signedData)),
        isTrue,
      );
    });
  });

  group('loadPublicKeyDer', () {
    test('loads a SubjectPublicKeyInfo and verifies an Ed25519 signature', () {
      final key = openSsl.generateEd25519();
      final signature = openSsl.sign(key, signedData);

      final publicKey = openSsl.loadPublicKeyDer(derOfPublicKey(key));
      expect(openSsl.verify(publicKey, signedData, signature), isTrue);
    });

    test('loads an EC (ES256) public key', () {
      final key = openSsl.generateEc('prime256v1');
      final signature = openSsl.sign(key, signedData);

      final publicKey = openSsl.loadPublicKeyDer(derOfPublicKey(key));
      expect(openSsl.verify(publicKey, signedData, signature), isTrue);
    });

    test('loadPublicKeyBytes auto-detects PEM and DER', () {
      final key = openSsl.generateEc('prime256v1');
      final pem = key.toPublicKeyPem();

      final fromPem =
          openSsl.loadPublicKeyBytes(Uint8List.fromList(pem.codeUnits));
      final fromDer = openSsl.loadPublicKeyBytes(derOfPublicKey(key));

      final signature = openSsl.sign(key, signedData);
      expect(openSsl.verify(fromPem, signedData, signature), isTrue);
      expect(openSsl.verify(fromDer, signedData, signature), isTrue);
    });

    test('rejects garbage with a clear error', () {
      expect(
        () => openSsl.loadPublicKeyDer(Uint8List.fromList([1, 2, 3])),
        throwsA(isA<OpenSslException>()),
      );
      expect(
        () => openSsl.loadPublicKeyDer(Uint8List(0)),
        throwsArgumentError,
      );
    });
  });
}
