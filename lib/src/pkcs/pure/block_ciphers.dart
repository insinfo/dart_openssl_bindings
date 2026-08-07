import 'dart:typed_data';

/// Block ciphers in pure Dart, limited to what PKCS#12 needs.
///
/// Only decryption is implemented — the goal is opening existing files,
/// including those encrypted with RC2, which OpenSSL 3.x moved out of the
/// default provider.

/// Contract of a block cipher.
abstract class BlockCipher {
  /// Block size, in bytes.
  int get blockSize;

  /// Decrypts a single [blockSize]-byte block (ECB mode).
  Uint8List decryptBlock(Uint8List block);
}

/// Decrypts [data] in CBC mode with [iv] and strips PKCS#7 padding.
Uint8List decryptCbc(
  BlockCipher cipher,
  Uint8List iv,
  Uint8List data, {
  bool removePadding = true,
}) {
  final block = cipher.blockSize;
  if (iv.length != block) {
    throw ArgumentError('IV of ${iv.length} bytes; expected $block');
  }
  if (data.isEmpty || data.length % block != 0) {
    throw ArgumentError(
      'Invalid CBC length: ${data.length} is not a multiple of $block',
    );
  }

  final output = Uint8List(data.length);
  var previous = iv;

  for (var i = 0; i < data.length; i += block) {
    final current = Uint8List.sublistView(data, i, i + block);
    final decrypted = cipher.decryptBlock(current);
    for (var j = 0; j < block; j++) {
      output[i + j] = decrypted[j] ^ previous[j];
    }
    previous = current;
  }

  return removePadding ? removePkcs7Padding(output, block) : output;
}

/// Strips PKCS#7 padding from [data].
Uint8List removePkcs7Padding(Uint8List data, int blockSize) {
  if (data.isEmpty) {
    throw ArgumentError('No data to unpad');
  }
  final pad = data.last;
  if (pad == 0 || pad > blockSize || pad > data.length) {
    throw const FormatException('Invalid PKCS#7 padding (wrong password?)');
  }
  for (var i = data.length - pad; i < data.length; i++) {
    if (data[i] != pad) {
      throw const FormatException('Invalid PKCS#7 padding (wrong password?)');
    }
  }
  return Uint8List.sublistView(data, 0, data.length - pad);
}

// -----------------------------------------------------------------------------
// RC2 (RFC 2268)
// -----------------------------------------------------------------------------

/// RC2 block cipher, as specified by RFC 2268.
///
/// [effectiveBits] is the effective key strength: 40 for
/// `pbeWithSHA1And40BitRC2-CBC` and 128 for the 128-bit variant.
class Rc2Cipher implements BlockCipher {
  final List<int> _k;

  Rc2Cipher(Uint8List key, int effectiveBits) : _k = _expandKey(key, effectiveBits);

  @override
  int get blockSize => 8;

  @override
  Uint8List decryptBlock(Uint8List block) {
    var r0 = block[0] | (block[1] << 8);
    var r1 = block[2] | (block[3] << 8);
    var r2 = block[4] | (block[5] << 8);
    var r3 = block[6] | (block[7] << 8);

    var j = 63;
    for (var round = 15; round >= 0; round--) {
      // The r-mash undoes the mashing applied after encryption rounds 4 and 10.
      if (round == 10 || round == 4) {
        r3 = (r3 - _k[r2 & 63]) & 0xffff;
        r2 = (r2 - _k[r1 & 63]) & 0xffff;
        r1 = (r1 - _k[r0 & 63]) & 0xffff;
        r0 = (r0 - _k[r3 & 63]) & 0xffff;
      }

      r3 = _ror16(r3, 5);
      r3 = (r3 - _k[j--] - (r2 & r1) - (~r2 & r0)) & 0xffff;

      r2 = _ror16(r2, 3);
      r2 = (r2 - _k[j--] - (r1 & r0) - (~r1 & r3)) & 0xffff;

      r1 = _ror16(r1, 2);
      r1 = (r1 - _k[j--] - (r0 & r3) - (~r0 & r2)) & 0xffff;

      r0 = _ror16(r0, 1);
      r0 = (r0 - _k[j--] - (r3 & r2) - (~r3 & r1)) & 0xffff;
    }

    return Uint8List.fromList([
      r0 & 0xff,
      (r0 >> 8) & 0xff,
      r1 & 0xff,
      (r1 >> 8) & 0xff,
      r2 & 0xff,
      (r2 >> 8) & 0xff,
      r3 & 0xff,
      (r3 >> 8) & 0xff,
    ]);
  }

  static List<int> _expandKey(Uint8List key, int effectiveBits) {
    if (key.isEmpty || key.length > 128) {
      throw ArgumentError('Invalid RC2 key: ${key.length} bytes');
    }

    final t = key.length;
    final t8 = (effectiveBits + 7) ~/ 8;
    final tm = 0xff >> ((8 - (effectiveBits % 8)) % 8);

    final l = Uint8List(128)..setRange(0, t, key);
    for (var i = t; i < 128; i++) {
      l[i] = _piTable[(l[i - 1] + l[i - t]) & 0xff];
    }
    l[128 - t8] = _piTable[l[128 - t8] & tm];
    for (var i = 127 - t8; i >= 0; i--) {
      l[i] = _piTable[l[i + 1] ^ l[i + t8]];
    }

    final k = List<int>.filled(64, 0);
    for (var i = 0; i < 64; i++) {
      k[i] = l[i * 2] | (l[i * 2 + 1] << 8);
    }
    return k;
  }

  static int _ror16(int value, int shift) =>
      ((value >> shift) | (value << (16 - shift))) & 0xffff;
}

// -----------------------------------------------------------------------------
// RC4
// -----------------------------------------------------------------------------

/// RC4. Being a stream cipher, encrypting and decrypting are the same op.
Uint8List rc4(Uint8List key, Uint8List data) {
  if (key.isEmpty) {
    throw ArgumentError('Empty RC4 key');
  }

  final s = Uint8List(256);
  for (var i = 0; i < 256; i++) {
    s[i] = i;
  }

  var j = 0;
  for (var i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    final tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  final output = Uint8List(data.length);
  var x = 0;
  var y = 0;
  for (var k = 0; k < data.length; k++) {
    x = (x + 1) & 0xff;
    y = (y + s[x]) & 0xff;
    final tmp = s[x];
    s[x] = s[y];
    s[y] = tmp;
    output[k] = data[k] ^ s[(s[x] + s[y]) & 0xff];
  }
  return output;
}

// -----------------------------------------------------------------------------
// DES / 3DES (FIPS 46-3)
// -----------------------------------------------------------------------------

/// Single DES. Used as a building block of [TripleDesCipher].
class DesCipher implements BlockCipher {
  final List<int> _subkeys;

  DesCipher(Uint8List key) : _subkeys = _buildSubkeys(key);

  @override
  int get blockSize => 8;

  @override
  Uint8List decryptBlock(Uint8List block) =>
      _process(block, _subkeys.reversed.toList());

  /// Encrypts a block (needed by the EDE chaining of 3DES).
  Uint8List encryptBlock(Uint8List block) => _process(block, _subkeys);

  Uint8List _process(Uint8List block, List<int> subkeys) {
    var data = _permute(_bytesToInt(block), _ip, 64);
    var l = (data >> 32) & 0xffffffff;
    var r = data & 0xffffffff;

    for (final k in subkeys) {
      final previous = r;
      r = l ^ _feistel(r, k);
      l = previous;
    }

    final preOutput = ((r & 0xffffffff) << 32) | (l & 0xffffffff);
    return _intToBytes(_permute(preOutput, _fp, 64), 8);
  }

  static int _feistel(int r, int k) {
    final e = _permute(r, _e, 32);
    final x = e ^ k;
    var output = 0;
    for (var i = 0; i < 8; i++) {
      final sixBits = (x >> (42 - i * 6)) & 0x3f;
      final row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
      final column = (sixBits >> 1) & 0x0f;
      output = (output << 4) | _sBoxes[i][row * 16 + column];
    }
    return _permute(output, _p, 32);
  }

  static List<int> _buildSubkeys(Uint8List key) {
    if (key.length != 8) {
      throw ArgumentError('DES key must be 8 bytes, got ${key.length}');
    }

    final permuted = _permute(_bytesToInt(key), _pc1, 64);
    var c = (permuted >> 28) & 0x0fffffff;
    var d = permuted & 0x0fffffff;

    final subkeys = <int>[];
    for (var i = 0; i < 16; i++) {
      c = _rotl28(c, _shifts[i]);
      d = _rotl28(d, _shifts[i]);
      subkeys.add(_permute((c << 28) | d, _pc2, 56));
    }
    return subkeys;
  }

  static int _rotl28(int value, int shift) {
    const mask = 0x0fffffff;
    return ((value << shift) & mask) |
        ((value & mask) >> (28 - shift));
  }
}

/// 3DES em EDE (chaves de 16 ou 24 bytes).
class TripleDesCipher implements BlockCipher {
  final DesCipher _k1;
  final DesCipher _k2;
  final DesCipher _k3;

  factory TripleDesCipher(Uint8List key) {
    if (key.length == 16) {
      return TripleDesCipher._(
        DesCipher(Uint8List.sublistView(key, 0, 8)),
        DesCipher(Uint8List.sublistView(key, 8, 16)),
        DesCipher(Uint8List.sublistView(key, 0, 8)),
      );
    }
    if (key.length == 24) {
      return TripleDesCipher._(
        DesCipher(Uint8List.sublistView(key, 0, 8)),
        DesCipher(Uint8List.sublistView(key, 8, 16)),
        DesCipher(Uint8List.sublistView(key, 16, 24)),
      );
    }
    throw ArgumentError('3DES key must be 16 or 24 bytes');
  }

  TripleDesCipher._(this._k1, this._k2, this._k3);

  @override
  int get blockSize => 8;

  @override
  Uint8List decryptBlock(Uint8List block) =>
      _k1.decryptBlock(_k2.encryptBlock(_k3.decryptBlock(block)));
}

// -----------------------------------------------------------------------------
// AES (FIPS 197)
// -----------------------------------------------------------------------------

/// AES-128/192/256, decryption only.
class AesCipher implements BlockCipher {
  final Uint8List _chaveExpandida;
  final int _rodadas;

  factory AesCipher(Uint8List key) {
    final rounds = switch (key.length) {
      16 => 10,
      24 => 12,
      32 => 14,
      _ => throw ArgumentError('AES key must be 16, 24 or 32 bytes'),
    };
    return AesCipher._(_expandKey(key, rounds), rounds);
  }

  AesCipher._(this._chaveExpandida, this._rodadas);

  @override
  int get blockSize => 16;

  @override
  Uint8List decryptBlock(Uint8List block) {
    final state = Uint8List.fromList(block);

    _adicionarChaveRodada(state, _rodadas);
    for (var round = _rodadas - 1; round >= 1; round--) {
      _invShiftRows(state);
      _invSubBytes(state);
      _adicionarChaveRodada(state, round);
      _invMixColumns(state);
    }
    _invShiftRows(state);
    _invSubBytes(state);
    _adicionarChaveRodada(state, 0);

    return state;
  }

  void _adicionarChaveRodada(Uint8List state, int round) {
    final start = round * 16;
    for (var i = 0; i < 16; i++) {
      state[i] ^= _chaveExpandida[start + i];
    }
  }

  static void _invSubBytes(Uint8List state) {
    for (var i = 0; i < 16; i++) {
      state[i] = _invSBox[state[i]];
    }
  }

  /// Undoes ShiftRows. The state is column-major: the byte at (row r,
  /// column c) lives at `state[c * 4 + r]`.
  static void _invShiftRows(Uint8List state) {
    final t = Uint8List.fromList(state);
    for (var column = 0; column < 4; column++) {
      for (var row = 1; row < 4; row++) {
        final origem = ((column - row) % 4 + 4) % 4;
        state[column * 4 + row] = t[origem * 4 + row];
      }
    }
  }

  static void _invMixColumns(Uint8List state) {
    for (var c = 0; c < 4; c++) {
      final a0 = state[c * 4];
      final a1 = state[c * 4 + 1];
      final a2 = state[c * 4 + 2];
      final a3 = state[c * 4 + 3];

      state[c * 4] =
          _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9);
      state[c * 4 + 1] =
          _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13);
      state[c * 4 + 2] =
          _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11);
      state[c * 4 + 3] =
          _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14);
    }
  }

  static int _mul(int a, int b) {
    var product = 0;
    var x = a;
    var y = b;
    for (var i = 0; i < 8; i++) {
      if (y & 1 != 0) product ^= x;
      final highBit = x & 0x80;
      x = (x << 1) & 0xff;
      if (highBit != 0) x ^= 0x1b;
      y >>= 1;
    }
    return product & 0xff;
  }

  static Uint8List _expandKey(Uint8List key, int rounds) {
    final nk = key.length ~/ 4;
    final total = 4 * (rounds + 1);
    final w = Uint8List(total * 4)..setRange(0, key.length, key);

    for (var i = nk; i < total; i++) {
      var t0 = w[(i - 1) * 4];
      var t1 = w[(i - 1) * 4 + 1];
      var t2 = w[(i - 1) * 4 + 2];
      var t3 = w[(i - 1) * 4 + 3];

      if (i % nk == 0) {
        final rot = t0;
        t0 = _sBox[t1] ^ _rcon[i ~/ nk];
        t1 = _sBox[t2];
        t2 = _sBox[t3];
        t3 = _sBox[rot];
      } else if (nk > 6 && i % nk == 4) {
        t0 = _sBox[t0];
        t1 = _sBox[t1];
        t2 = _sBox[t2];
        t3 = _sBox[t3];
      }

      w[i * 4] = w[(i - nk) * 4] ^ t0;
      w[i * 4 + 1] = w[(i - nk) * 4 + 1] ^ t1;
      w[i * 4 + 2] = w[(i - nk) * 4 + 2] ^ t2;
      w[i * 4 + 3] = w[(i - nk) * 4 + 3] ^ t3;
    }

    return w;
  }
}

// -----------------------------------------------------------------------------
// Tables and helpers
// -----------------------------------------------------------------------------

int _permute(int input, List<int> table, int inputBits) {
  var output = 0;
  for (var i = 0; i < table.length; i++) {
    final bit = (input >> (inputBits - table[i])) & 0x01;
    output = (output << 1) | bit;
  }
  return output;
}

int _bytesToInt(Uint8List bytes) {
  var value = 0;
  for (final b in bytes) {
    value = (value << 8) | b;
  }
  return value;
}

Uint8List _intToBytes(int value, int length) {
  final out = Uint8List(length);
  var v = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = v & 0xff;
    v >>= 8;
  }
  return out;
}

const List<int> _piTable = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, //
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

const List<int> _ip = [
  58, 50, 42, 34, 26, 18, 10, 2, //
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
];

const List<int> _fp = [
  40, 8, 48, 16, 56, 24, 64, 32, //
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25,
];

const List<int> _e = [
  32, 1, 2, 3, 4, 5, //
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1,
];

const List<int> _p = [
  16, 7, 20, 21, 29, 12, 28, 17, //
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25,
];

const List<int> _pc1 = [
  57, 49, 41, 33, 25, 17, 9, //
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4,
];

const List<int> _pc2 = [
  14, 17, 11, 24, 1, 5, //
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
];

const List<int> _shifts = [
  1, 1, 2, 2, 2, 2, 2, 2, //
  1, 2, 2, 2, 2, 2, 2, 1,
];

const List<List<int>> _sBoxes = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, //
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, //
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, //
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, //
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, //
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, //
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, //
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, //
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

const List<int> _rcon = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, //
  0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];

const List<int> _sBox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, //
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const List<int> _invSBox = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, //
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];
