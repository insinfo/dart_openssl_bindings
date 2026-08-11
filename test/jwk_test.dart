import 'dart:convert';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:openssl_bindings/src/pkcs/pure/der.dart';
import 'package:test/test.dart';

/// Strips the PEM armour and returns the DER body.
Uint8List _pemBody(String pem) => Uint8List.fromList(
      base64.decode(
        pem
            .split('\n')
            .where((l) => !l.startsWith('-----') && l.trim().isNotEmpty)
            .join(),
      ),
    );

/// The unsigned magnitude of a DER INTEGER, without the sign byte DER adds.
Uint8List _magnitude(DerValue integer) =>
    integer.content.length > 1 && integer.content[0] == 0
        ? Uint8List.sublistView(integer.content, 1)
        : integer.content;

/// Pulls the nine PKCS#1 integers out of a key's PKCS#8 PEM export.
///
/// Building the test JWKs from a freshly generated key — rather than a
/// hard-coded blob — means the CRT-derivation path is checked against a real
/// modulus on every run.
List<DerValue> _pkcs1Integers(EvpPkey key) {
  final pkcs8 = DerReader(_pemBody(key.toPrivateKeyPem())).read().elements;
  return DerReader(pkcs8[2].octets).read().elements;
}

/// A private JWK carrying only `n`, `e`, `d`, `p` and `q` — the shape
/// `package:jose` produces, with the optional CRT parameters left out.
Map<String, Object?> _minimalPrivateJwk(EvpPkey key) {
  final i = _pkcs1Integers(key);
  return <String, Object?>{
    'kty': 'RSA',
    'n': encodeBase64Url(_magnitude(i[1])),
    'e': encodeBase64Url(_magnitude(i[2])),
    'd': encodeBase64Url(_magnitude(i[3])),
    'p': encodeBase64Url(_magnitude(i[4])),
    'q': encodeBase64Url(_magnitude(i[5])),
  };
}

/// The same key as a complete JWK, CRT parameters included.
Map<String, Object?> _fullPrivateJwk(EvpPkey key) {
  final i = _pkcs1Integers(key);
  return <String, Object?>{
    ..._minimalPrivateJwk(key),
    'dp': encodeBase64Url(_magnitude(i[6])),
    'dq': encodeBase64Url(_magnitude(i[7])),
    'qi': encodeBase64Url(_magnitude(i[8])),
  };
}

/// RFC 7517 appendix A.1, the canonical RSA public JWK.
const _rfc7517PublicJwk = <String, Object?>{
  'kty': 'RSA',
  'n': '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7a'
      'PFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl'
      '93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgd'
      'AZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr'
      '3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  'e': 'AQAB',
};

void main() {
  late OpenSSL openSsl;

  setUp(() => openSsl = OpenSSL());

  group('RSA public JWK', () {
    test('loads the RFC 7517 example key', () {
      final key = openSsl.loadPublicKeyJwk(_rfc7517PublicJwk);
      try {
        expect(key.toPublicKeyPem(), startsWith('-----BEGIN PUBLIC KEY-----'));
      } finally {
        key.dispose();
      }
    });

    test('survives a round trip through DER', () {
      final key = openSsl.loadPublicKeyJwk(_rfc7517PublicJwk);
      try {
        final jwk = key.toPublicJwk();
        expect(jwk['kty'], equals('RSA'));
        expect(jwk['n'], equals(_rfc7517PublicJwk['n']));
        expect(jwk['e'], equals(_rfc7517PublicJwk['e']));
      } finally {
        key.dispose();
      }
    });

    test('carries the metadata a jwks_uri needs', () {
      final key = openSsl.loadPublicKeyJwk(_rfc7517PublicJwk);
      try {
        final jwk =
            key.toPublicJwk(keyId: 'sali-idp-1', algorithm: 'RS256', use: 'sig');
        expect(jwk['kid'], equals('sali-idp-1'));
        expect(jwk['alg'], equals('RS256'));
        expect(jwk['use'], equals('sig'));
      } finally {
        key.dispose();
      }
    });

    test('omits metadata that was not asked for', () {
      final key = openSsl.loadPublicKeyJwk(_rfc7517PublicJwk);
      try {
        final jwk = key.toPublicJwk();
        expect(jwk.containsKey('kid'), isFalse);
        expect(jwk.containsKey('alg'), isFalse);
        expect(jwk.containsKey('use'), isFalse);
      } finally {
        key.dispose();
      }
    });
  });

  group('RSA private JWK', () {
    late EvpPkey generated;
    final data = Uint8List.fromList(utf8.encode('id_token signing input'));

    setUp(() => generated = openSsl.generateRsa(2048));
    tearDown(() => generated.dispose());

    test('a complete JWK signs what its public half verifies', () {
      final jwk = _fullPrivateJwk(generated);
      final privateKey = openSsl.loadPrivateKeyJwk(jwk);
      final publicKey = openSsl.loadPublicKeyJwk(jwk);
      try {
        final signature = openSsl.sign(privateKey, data);
        expect(openSsl.verify(publicKey, data, signature), isTrue);

        final tampered = Uint8List.fromList(data)..[0] ^= 0xFF;
        expect(openSsl.verify(publicKey, tampered, signature), isFalse);
      } finally {
        privateKey.dispose();
        publicKey.dispose();
      }
    });

    test('a JWK without CRT parameters produces the same signature', () {
      // `dp`, `dq` and `qi` are optional in a JWK — `package:jose` omits them
      // when it generates a key — so the loader derives them. RS256 is
      // deterministic, so a wrong derivation cannot hide: the bytes would
      // differ from the same key carrying its own CRT parameters.
      final withCrt = openSsl.loadPrivateKeyJwk(_fullPrivateJwk(generated));
      final withoutCrt =
          openSsl.loadPrivateKeyJwk(_minimalPrivateJwk(generated));
      try {
        expect(
          openSsl.sign(withoutCrt, data),
          equals(openSsl.sign(withCrt, data)),
        );
      } finally {
        withCrt.dispose();
        withoutCrt.dispose();
      }
    });

    test('the key from a JWK matches the key it came from', () {
      final fromJwk =
          openSsl.loadPrivateKeyJwk(_minimalPrivateJwk(generated));
      try {
        // Same key material by two different routes: the signature the JWK
        // makes must verify against the original key's public half.
        expect(fromJwk.toPublicKeyPem(), equals(generated.toPublicKeyPem()));
        expect(
          openSsl.verify(generated, data, openSsl.sign(fromJwk, data)),
          isTrue,
        );
      } finally {
        fromJwk.dispose();
      }
    });

    test('a private JWK also yields the public key', () {
      // One key file, both halves: sign with the private, publish the public.
      final publicKey =
          openSsl.loadPublicKeyJwk(_minimalPrivateJwk(generated));
      try {
        expect(publicKey.toPublicKeyPem(), equals(generated.toPublicKeyPem()));
        expect(
          openSsl.verify(publicKey, data, openSsl.sign(generated, data)),
          isTrue,
        );
      } finally {
        publicKey.dispose();
      }
    });

    test('round trips to a public JWK and back', () {
      final jwk = _fullPrivateJwk(generated);
      final loaded = openSsl.loadPrivateKeyJwk(jwk);
      try {
        final exported = loaded.toPublicJwk(algorithm: 'RS256', use: 'sig');
        expect(exported['n'], equals(jwk['n']));
        expect(exported['e'], equals(jwk['e']));

        final reloaded = openSsl.loadPublicKeyJwk(exported);
        try {
          expect(
            openSsl.verify(reloaded, data, openSsl.sign(loaded, data)),
            isTrue,
          );
        } finally {
          reloaded.dispose();
        }
      } finally {
        loaded.dispose();
      }
    });
  });

  group('Rejections', () {
    test('rejects a non-RSA JWK', () {
      expect(
        () => openSsl.loadPublicKeyJwk(const {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'AA',
          'y': 'AA',
        }),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a JWK missing a required parameter', () {
      expect(
        () => openSsl.loadPublicKeyJwk(const {'kty': 'RSA', 'e': 'AQAB'}),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => openSsl.loadPrivateKeyJwk({
          ..._rfc7517PublicJwk,
          'd': 'AQAB',
          // no p / q
        }),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects an empty DER private key', () {
      expect(
        () => openSsl.loadPrivateKeyDer(Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects garbage DER', () {
      expect(
        () => openSsl.loadPrivateKeyDer(Uint8List.fromList([1, 2, 3, 4])),
        throwsA(isA<OpenSslException>()),
      );
    });
  });

  group('DER private keys', () {
    test('loadPrivateKeyDer reads back what the key exports', () {
      final generated = openSsl.generateRsa(2048);
      try {
        // PKCS#8 PEM -> strip armour -> DER -> load again.
        final pem = generated.toPrivateKeyPem();
        final body = pem
            .split('\n')
            .where((line) => !line.startsWith('-----') && line.trim().isNotEmpty)
            .join();
        final der = Uint8List.fromList(base64.decode(body));

        final reloaded = openSsl.loadPrivateKeyDer(der);
        try {
          final data = Uint8List.fromList(utf8.encode('der round trip'));
          final publicKey = openSsl.loadPublicKeyPem(generated.toPublicKeyPem());
          try {
            expect(
              openSsl.verify(publicKey, data, openSsl.sign(reloaded, data)),
              isTrue,
            );
          } finally {
            publicKey.dispose();
          }
        } finally {
          reloaded.dispose();
        }
      } finally {
        generated.dispose();
      }
    });

    test('toPublicKeyDer matches the PEM export', () {
      final key = openSsl.generateRsa(2048);
      try {
        final der = key.toPublicKeyDer();
        final fromDer = openSsl.loadPublicKeyDer(der);
        try {
          expect(fromDer.toPublicKeyPem(), equals(key.toPublicKeyPem()));
        } finally {
          fromDer.dispose();
        }
      } finally {
        key.dispose();
      }
    });
  });

  group('base64url', () {
    test('decodes unpadded input, as every JWK uses', () {
      expect(decodeBase64Url('AQAB'), equals([0x01, 0x00, 0x01]));
      // 'e' from a JWK is unpadded; so is any value whose length is not a
      // multiple of four.
      expect(encodeBase64Url([0x01, 0x00, 0x01]), equals('AQAB'));
      expect(encodeBase64Url([0xFF, 0xFE]), isNot(contains('=')));
    });

    test('round trips the URL-safe alphabet', () {
      final bytes = Uint8List.fromList(List<int>.generate(256, (i) => i));
      expect(decodeBase64Url(encodeBase64Url(bytes)), equals(bytes));
      expect(encodeBase64Url(bytes), isNot(anyOf(contains('+'), contains('/'))));
    });
  });
}

