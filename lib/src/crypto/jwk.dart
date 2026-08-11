import 'dart:convert';
import 'dart:typed_data';

import '../pkcs/pure/der.dart';

/// Conversion between JSON Web Keys (RFC 7517) and the DER encodings OpenSSL
/// reads, in pure Dart.
///
/// A JWK carries an RSA key as base64url big-endian integers; OpenSSL wants
/// PKCS#1 or SubjectPublicKeyInfo. Translating between the two is pure
/// structure work — no FFI and no crypto — which is why it lives here rather
/// than in a mixin, and why it is cheap enough to do at startup.
///
/// Only RSA keys are handled. An OpenID Connect identity provider signing with
/// RS256 — the common case, and what this exists for — is RSA; EC and OKP JWKs
/// throw rather than silently producing a key that cannot verify anything.

/// Decodes base64url, the encoding every JWK integer uses.
///
/// Padding is restored before decoding, so input both with and without `=`
/// works — RFC 7515 §2 requires it omitted, but not every implementation obeys
/// (`package:jose` emits it), and rejecting those keys would help nobody.
Uint8List decodeBase64Url(String value) {
  final normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  final padded = normalized.padRight((normalized.length + 3) & ~3, '=');
  return Uint8List.fromList(base64.decode(padded));
}

/// Encodes [bytes] as base64url without padding, as RFC 7515 §2 requires.
String encodeBase64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Encodes [magnitude] as a DER INTEGER.
///
/// DER integers are signed, so a leading zero byte goes in front of any value
/// whose top bit is set — without it OpenSSL reads a 2048-bit modulus as a
/// negative number and the key fails to load.
Uint8List _derInteger(Uint8List magnitude) {
  var start = 0;
  while (start < magnitude.length - 1 && magnitude[start] == 0) {
    start++;
  }
  final trimmed = Uint8List.sublistView(magnitude, start);
  if (trimmed.isEmpty) return DerValue(0x02, Uint8List(1)).bytes;

  final content = trimmed[0] & 0x80 == 0
      ? trimmed
      : (Uint8List(trimmed.length + 1)
        ..setRange(1, trimmed.length + 1, trimmed));
  return DerValue(0x02, content).bytes;
}

Uint8List _derSequence(List<Uint8List> elements) {
  final body = BytesBuilder(copy: false);
  for (final element in elements) {
    body.add(element);
  }
  return DerValue(0x30, body.toBytes()).bytes;
}

BigInt _toBigInt(Uint8List bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _fromBigInt(BigInt value) {
  if (value <= BigInt.zero) return Uint8List(1);
  final bytes = <int>[];
  var remaining = value;
  final mask = BigInt.from(0xFF);
  while (remaining > BigInt.zero) {
    bytes.insert(0, (remaining & mask).toInt());
    remaining >>= 8;
  }
  return Uint8List.fromList(bytes);
}

/// `AlgorithmIdentifier { rsaEncryption, NULL }`, the prefix of an RSA
/// SubjectPublicKeyInfo.
const List<int> _rsaAlgorithmIdentifier = <int>[
  0x30, 0x0d, //
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, //
  0x05, 0x00,
];

Uint8List _requireField(Map<String, Object?> jwk, String name) {
  final value = jwk[name];
  if (value is! String || value.isEmpty) {
    throw FormatException('JWK is missing the required "$name" parameter');
  }
  return decodeBase64Url(value);
}

void _requireRsa(Map<String, Object?> jwk) {
  final kty = jwk['kty'];
  if (kty != 'RSA') {
    throw FormatException(
      'Only RSA JWKs are supported, got kty="$kty". '
      'Load EC and OKP keys from PEM or DER instead.',
    );
  }
}

/// Builds a PKCS#1 `RSAPrivateKey` DER from the private half of an RSA [jwk].
///
/// The CRT parameters (`dp`, `dq`, `qi`) are optional in a JWK — some
/// generators omit them — but PKCS#1 requires all nine integers, so they are
/// derived from `d`, `p` and `q` when absent.
Uint8List rsaPrivateKeyDerFromJwk(Map<String, Object?> jwk) {
  _requireRsa(jwk);

  final n = _requireField(jwk, 'n');
  final e = _requireField(jwk, 'e');
  final d = _requireField(jwk, 'd');
  final p = _requireField(jwk, 'p');
  final q = _requireField(jwk, 'q');

  final dBig = _toBigInt(d);
  final pBig = _toBigInt(p);
  final qBig = _toBigInt(q);
  if (pBig <= BigInt.one || qBig <= BigInt.one) {
    throw const FormatException('JWK has invalid RSA primes');
  }

  Uint8List optional(String name, BigInt Function() derive) {
    final present = jwk[name];
    return present is String && present.isNotEmpty
        ? decodeBase64Url(present)
        : _fromBigInt(derive());
  }

  return _derSequence([
    _derInteger(Uint8List.fromList(const [0])), // version: two-prime
    _derInteger(n),
    _derInteger(e),
    _derInteger(d),
    _derInteger(p),
    _derInteger(q),
    _derInteger(optional('dp', () => dBig % (pBig - BigInt.one))),
    _derInteger(optional('dq', () => dBig % (qBig - BigInt.one))),
    _derInteger(optional('qi', () => qBig.modInverse(pBig))),
  ]);
}

/// Builds a SubjectPublicKeyInfo DER from the public half of an RSA [jwk].
///
/// Works for a private JWK too — the extra parameters are simply ignored, so
/// the same key file can produce both halves.
Uint8List rsaPublicKeyDerFromJwk(Map<String, Object?> jwk) {
  _requireRsa(jwk);

  final pkcs1 = _derSequence([
    _derInteger(_requireField(jwk, 'n')),
    _derInteger(_requireField(jwk, 'e')),
  ]);

  // BIT STRING with zero unused bits, wrapping the PKCS#1 key.
  final bitString = Uint8List(pkcs1.length + 1)..setRange(1, pkcs1.length + 1, pkcs1);
  return _derSequence([
    Uint8List.fromList(_rsaAlgorithmIdentifier),
    DerValue(0x03, bitString).bytes,
  ]);
}

/// Reads an RSA SubjectPublicKeyInfo DER back into a public JWK.
///
/// The inverse of [rsaPublicKeyDerFromJwk], for publishing a key at a
/// `jwks_uri`. Only `kty`, `n` and `e` come from the key itself; [keyId],
/// [algorithm] and [use] are metadata the caller chooses.
Map<String, Object?> rsaJwkFromSpkiDer(
  Uint8List spki, {
  String? keyId,
  String? algorithm,
  String? use,
}) {
  final outer = DerReader(spki).read();
  if (outer.tag != 0x30) {
    throw const FormatException('Not a SubjectPublicKeyInfo: expected SEQUENCE');
  }

  final parts = outer.elements;
  if (parts.length < 2 || parts[1].tag != 0x03) {
    throw const FormatException(
      'Not a SubjectPublicKeyInfo: expected an AlgorithmIdentifier '
      'followed by a BIT STRING',
    );
  }

  final algorithmOid = parts[0].elements.first.oid;
  if (algorithmOid != '1.2.840.113549.1.1.1') {
    throw FormatException(
      'Only RSA public keys convert to a JWK here, got OID $algorithmOid',
    );
  }

  // Drop the "unused bits" byte that opens every BIT STRING.
  final keyBytes = Uint8List.sublistView(parts[1].content, 1);
  final rsaKey = DerReader(keyBytes).read().elements;
  if (rsaKey.length < 2) {
    throw const FormatException('Malformed RSAPublicKey: expected n and e');
  }

  Uint8List magnitude(DerValue integer) {
    final content = integer.content;
    // Strip the sign byte DER added; a JWK integer is unsigned.
    return content.length > 1 && content[0] == 0
        ? Uint8List.sublistView(content, 1)
        : content;
  }

  return <String, Object?>{
    'kty': 'RSA',
    'n': encodeBase64Url(magnitude(rsaKey[0])),
    'e': encodeBase64Url(magnitude(rsaKey[1])),
    if (keyId != null) 'kid': keyId,
    if (algorithm != null) 'alg': algorithm,
    if (use != null) 'use': use,
  };
}
