import 'dart:typed_data';

/// Hash, HMAC and KDF primitives in pure Dart.
///
/// They exist so the pure PKCS#12 decoder ([decodePkcs12Pure]) can run without
/// FFI and without OpenSSL's `legacy` provider.

/// Supported hash algorithms.
enum PureHash {
  sha1('SHA-1', 20),
  sha256('SHA-256', 32);

  const PureHash(this.name, this.digestSize);

  /// Usual algorithm name.
  final String name;

  /// Digest size, in bytes.
  final int digestSize;

  /// Internal block size in bytes (used by HMAC and by the PKCS#12 KDF).
  int get blockSize => 64;

  /// Computes the digest of [data].
  Uint8List digest(Uint8List data) {
    switch (this) {
      case PureHash.sha1:
        return sha1Digest(data);
      case PureHash.sha256:
        return sha256Digest(data);
    }
  }
}

/// SHA-1 of [data].
Uint8List sha1Digest(Uint8List data) {
  var h0 = 0x67452301;
  var h1 = 0xEFCDAB89;
  var h2 = 0x98BADCFE;
  var h3 = 0x10325476;
  var h4 = 0xC3D2E1F0;

  final blocks = _padBigEndian(data, 64);
  final w = Uint32List(80);

  for (var offset = 0; offset < blocks.length; offset += 64) {
    for (var i = 0; i < 16; i++) {
      final j = offset + i * 4;
      w[i] = (blocks[j] << 24) |
          (blocks[j + 1] << 16) |
          (blocks[j + 2] << 8) |
          blocks[j + 3];
    }
    for (var i = 16; i < 80; i++) {
      w[i] = _rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    var a = h0, b = h1, c = h2, d = h3, e = h4;
    for (var i = 0; i < 80; i++) {
      int f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      final temp = (_rotl32(a, 5) + (f & 0xFFFFFFFF) + e + k + w[i]) & 0xFFFFFFFF;
      e = d;
      d = c;
      c = _rotl32(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) & 0xFFFFFFFF;
    h1 = (h1 + b) & 0xFFFFFFFF;
    h2 = (h2 + c) & 0xFFFFFFFF;
    h3 = (h3 + d) & 0xFFFFFFFF;
    h4 = (h4 + e) & 0xFFFFFFFF;
  }

  final out = Uint8List(20);
  final bd = ByteData.view(out.buffer);
  bd.setUint32(0, h0);
  bd.setUint32(4, h1);
  bd.setUint32(8, h2);
  bd.setUint32(12, h3);
  bd.setUint32(16, h4);
  return out;
}

/// SHA-256 of [data].
Uint8List sha256Digest(Uint8List data) => _sha2_32(data, _iv256);

/// HMAC of [data] under [key], using [hash].
Uint8List hmac(PureHash hash, Uint8List key, Uint8List data) {
  final block = hash.blockSize;
  var k = key.length > block ? hash.digest(key) : key;

  final kPad = Uint8List(block)..setRange(0, k.length, k);
  final ipad = Uint8List(block);
  final opad = Uint8List(block);
  for (var i = 0; i < block; i++) {
    ipad[i] = kPad[i] ^ 0x36;
    opad[i] = kPad[i] ^ 0x5c;
  }

  final inner = hash.digest(_concat([ipad, data]));
  return hash.digest(_concat([opad, inner]));
}

/// PBKDF2-HMAC (RFC 2898), used by PBES2.
Uint8List pbkdf2(
  PureHash hash,
  Uint8List password,
  Uint8List salt,
  int iterations,
  int length,
) {
  if (iterations < 1) {
    throw ArgumentError.value(iterations, 'iterations', 'deve ser >= 1');
  }

  final hLen = hash.digestSize;
  final blocks = (length + hLen - 1) ~/ hLen;
  final output = Uint8List(length);
  var offset = 0;

  for (var i = 1; i <= blocks; i++) {
    final input = Uint8List(salt.length + 4)
      ..setRange(0, salt.length, salt)
      ..buffer.asByteData().setUint32(salt.length, i);

    var u = hmac(hash, password, input);
    final t = Uint8List.fromList(u);
    for (var j = 1; j < iterations; j++) {
      u = hmac(hash, password, u);
      for (var k = 0; k < t.length; k++) {
        t[k] ^= u[k];
      }
    }

    final toCopy = (offset + hLen > length) ? length - offset : hLen;
    output.setRange(offset, offset + toCopy, t);
    offset += toCopy;
  }

  return output;
}

/// Purpose identifiers of the PKCS#12 KDF (RFC 7292, appendix B.3).
class KdfPurpose {
  /// Derives key material.
  static const int key = 1;

  /// Derives an initialization vector.
  static const int iv = 2;

  /// Derives the integrity (MAC) key.
  static const int mac = 3;
}

/// PKCS#12 KDF (RFC 7292, appendix B.2).
///
/// [password] must be a NUL-terminated BMPString — use [passwordToBmp].
Uint8List pkcs12Kdf(
  PureHash hash,
  Uint8List password,
  Uint8List salt,
  int iterations,
  int purpose,
  int length,
) {
  final u = hash.digestSize;
  final v = hash.blockSize;

  final d = Uint8List(v)..fillRange(0, v, purpose);
  final s = _repeatTo(salt, v);
  final p = _repeatTo(password, v);
  final i = Uint8List(s.length + p.length)
    ..setRange(0, s.length, s)
    ..setRange(s.length, s.length + p.length, p);

  final c = (length + u - 1) ~/ u;
  final output = Uint8List(length);
  var offset = 0;

  for (var step = 0; step < c; step++) {
    var a = hash.digest(_concat([d, i]));
    for (var j = 1; j < iterations; j++) {
      a = hash.digest(a);
    }

    final toCopy = (offset + u > length) ? length - offset : u;
    output.setRange(offset, offset + toCopy, a);
    offset += toCopy;

    if (step == c - 1) break;

    // B = A repeated up to v bytes; I_j = (I_j + B + 1) mod 2^(v*8)
    final b = _repeatTo(a, v);
    for (var j = 0; j < i.length; j += v) {
      _addModulo(i, j, b, v);
    }
  }

  return output;
}

/// Converts the password to a NUL-terminated BMPString (UTF-16BE), as
/// PKCS#12 requires. An empty password becomes two zero bytes.
Uint8List passwordToBmp(String password) {
  final units = password.codeUnits;
  final out = Uint8List((units.length + 1) * 2);
  for (var i = 0; i < units.length; i++) {
    out[i * 2] = (units[i] >> 8) & 0xff;
    out[i * 2 + 1] = units[i] & 0xff;
  }
  return out;
}

/// Constant-time comparison.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

void _addModulo(Uint8List target, int offset, Uint8List b, int v) {
  var carry = 1;
  for (var i = v - 1; i >= 0; i--) {
    final soma = target[offset + i] + b[i] + carry;
    target[offset + i] = soma & 0xff;
    carry = soma >> 8;
  }
}

Uint8List _repeatTo(Uint8List input, int block) {
  if (input.isEmpty) return Uint8List(0);
  final length = ((input.length + block - 1) ~/ block) * block;
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = input[i % input.length];
  }
  return out;
}

Uint8List _concat(List<List<int>> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}

int _rotl32(int x, int n) =>
    ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n));

int _rotr32(int x, int n) =>
    ((x & 0xFFFFFFFF) >> n) | ((x << (32 - n)) & 0xFFFFFFFF);

/// Merkle-Damgard padding with a 64-bit big-endian bit counter.
Uint8List _padBigEndian(Uint8List data, int block) {
  final bits = data.length * 8;
  var total = data.length + 1;
  final rest = total % block;
  final padding = rest <= block - 8 ? block - 8 - rest : block * 2 - 8 - rest;
  total += padding;

  final out = Uint8List(total + 8);
  out.setRange(0, data.length, data);
  out[data.length] = 0x80;
  ByteData.view(out.buffer).setUint64(out.length - 8, bits);
  return out;
}

const List<int> _iv256 = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const List<int> _k256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

Uint8List _sha2_32(Uint8List data, List<int> iv) {
  final h = List<int>.from(iv);
  final blocks = _padBigEndian(data, 64);
  final w = Uint32List(64);

  for (var offset = 0; offset < blocks.length; offset += 64) {
    for (var i = 0; i < 16; i++) {
      final j = offset + i * 4;
      w[i] = (blocks[j] << 24) |
          (blocks[j + 1] << 16) |
          (blocks[j + 2] << 8) |
          blocks[j + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF;
    }

    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];

    for (var i = 0; i < 64; i++) {
      final s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
      final ch = (e & f) ^ (~e & g);
      final temp1 = (hh + s1 + (ch & 0xFFFFFFFF) + _k256[i] + w[i]) & 0xFFFFFFFF;
      final s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xFFFFFFFF;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xFFFFFFFF;
    }

    h[0] = (h[0] + a) & 0xFFFFFFFF;
    h[1] = (h[1] + b) & 0xFFFFFFFF;
    h[2] = (h[2] + c) & 0xFFFFFFFF;
    h[3] = (h[3] + d) & 0xFFFFFFFF;
    h[4] = (h[4] + e) & 0xFFFFFFFF;
    h[5] = (h[5] + f) & 0xFFFFFFFF;
    h[6] = (h[6] + g) & 0xFFFFFFFF;
    h[7] = (h[7] + hh) & 0xFFFFFFFF;
  }

  final out = Uint8List(32);
  final bd = ByteData.view(out.buffer);
  for (var i = 0; i < 8; i++) {
    bd.setUint32(i * 4, h[i]);
  }
  return out;
}
