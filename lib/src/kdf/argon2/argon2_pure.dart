// Pure Dart Argon2 (Argon2d / Argon2i / Argon2id), RFC 9106.
//
// Fallback for a libcrypto that predates OpenSSL 3.2 and has no native
// Argon2. Self-contained on purpose: nothing beyond dart:typed_data.
//
// Written for the Dart VM, not for the web. It relies on `int` being a 64-bit
// two's-complement integer with wrapping arithmetic, on `>>>`, and on
// `Uint64List`. The block memory is one flat `Uint64List`, the compression
// function G runs on native 64-bit words, and the permutation P is unrolled
// over locals so each of its 16 rounds touches memory only to load and store
// its 16 words. That is what makes this several times faster than the JS-safe
// variant (32-bit halves, BigInt BLAKE2b) the SALI core keeps for its captcha
// solver, which this file originally descended from.
//
// Prefer the [Argon2Mixin] facade in ../argon2.dart: it uses OpenSSL's native
// implementation when available and falls back to this one otherwise.
//
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

// ============================================================================
// PARAMETERS
// ============================================================================

/// Inputs to a derivation other than the password: variant, costs, salt and
/// the optional secret and associated data.
class Argon2Parameters {
  static const int ARGON2_d = 0x00;
  static const int ARGON2_i = 0x01;
  static const int ARGON2_id = 0x02;

  static const int ARGON2_VERSION_10 = 0x10;
  static const int ARGON2_VERSION_13 = 0x13;

  static const int DEFAULT_ITERATIONS = 3;
  static const int DEFAULT_MEMORY_COST = 12;
  static const int DEFAULT_LANES = 1;
  static const int DEFAULT_TYPE = ARGON2_i;
  static const int DEFAULT_VERSION = ARGON2_VERSION_13;

  final int type;
  final Uint8List salt;
  final Uint8List? secret;
  final Uint8List? additional;

  final int iterations;

  /// Memory cost in KiB (one block per KiB), as requested by the caller. The
  /// generator rounds it down to a multiple of `4 * lanes` internally, but
  /// this original value is what goes into the initial hash.
  final int memory;
  final int lanes;
  final int version;

  Argon2Parameters(
    this.type,
    this.salt, {
    this.secret,
    this.additional,
    this.iterations = DEFAULT_ITERATIONS,
    int? memoryPowerOf2,
    int? memory,
    this.lanes = DEFAULT_LANES,
    this.version = DEFAULT_VERSION,
  }) : memory = memoryPowerOf2 != null
            ? 1 << memoryPowerOf2
            : (memory ?? (1 << DEFAULT_MEMORY_COST));

  @override
  String toString() =>
      'Argon2Parameters{ type: $type, iterations: $iterations, '
      'memory: $memory, lanes: $lanes, version: $version }';
}

// ============================================================================
// ARGON2 CORE
// ============================================================================

/// The Argon2 memory-hard function. `init` sizes and allocates the block
/// memory; `generateBytes` runs one derivation. The memory is wiped after
/// each derivation and can be reused for the next one.
class Argon2BytesGenerator {
  static const int ARGON2_BLOCK_SIZE = 1024;
  static const int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE ~/ 8;
  static const int ARGON2_ADDRESSES_IN_BLOCK = 128;
  static const int ARGON2_PREHASH_DIGEST_LENGTH = 64;
  static const int ARGON2_PREHASH_SEED_LENGTH = 72;
  static const int ARGON2_SYNC_POINTS = 4;
  static const int MIN_PARALLELISM = 1;
  static const int MAX_PARALLELISM = 16777216;
  static const int MIN_OUTLEN = 4;
  static const int MIN_ITERATIONS = 1;

  static const int _m32 = 0xFFFFFFFF;

  /// Bit 63. OR-ed into one operand of the `lo32(a) * lo32(b)` product in
  /// the permutation: it does not change the result — the extra 2^63 * lo32(b)
  /// is either 0 or 2^63 mod 2^64, and the `<< 1` that follows drops it — but
  /// it keeps the JIT from speculating a Smi multiply on two 32-bit operands,
  /// overflowing, deoptimising at each of the 32 sites and, past its deopt
  /// budget, giving up on optimising the function at all (about 200x slower).
  static const int _hi = 0x8000000000000000;

  /// Words per block; block `b` lives at `_memory[b * _q .. b * _q + _q)`.
  static const int _q = ARGON2_QWORDS_IN_BLOCK;

  late Argon2Parameters _parameters;

  /// All blocks, contiguous: `_memoryBlocks * 128` little-endian words.
  late Uint64List _memory;
  late int _memoryBlocks;
  late int _segmentLength;
  late int _laneLength;

  // Scratch blocks, reused for every block filled.
  final Uint64List _z = Uint64List(_q);
  final Uint64List _addressBlock = Uint64List(_q);
  final Uint64List _inputBlock = Uint64List(_q);
  final Uint64List _zeroBlock = Uint64List(_q);

  Argon2BytesGenerator();

  Argon2Parameters get parameters => _parameters;

  void init(Argon2Parameters parameters) {
    _parameters = parameters;

    if (parameters.lanes < MIN_PARALLELISM) {
      throw ArgumentError.value(parameters.lanes, 'parameters.lanes',
          'lanes must be at least $MIN_PARALLELISM');
    } else if (parameters.lanes > MAX_PARALLELISM) {
      throw ArgumentError.value(parameters.lanes, 'parameters.lanes',
          'lanes must be at most $MAX_PARALLELISM');
    } else if (parameters.memory < 2 * parameters.lanes) {
      throw ArgumentError.value(parameters.memory, 'parameters.memory',
          'memory must be at least ${2 * parameters.lanes}');
    } else if (parameters.iterations < MIN_ITERATIONS) {
      throw ArgumentError.value(parameters.iterations, 'parameters.iterations',
          'iterations must be at least $MIN_ITERATIONS');
    }

    var memoryBlocks = parameters.memory;
    final minimum = 2 * ARGON2_SYNC_POINTS * parameters.lanes;
    if (memoryBlocks < minimum) memoryBlocks = minimum;

    _segmentLength = memoryBlocks ~/ (parameters.lanes * ARGON2_SYNC_POINTS);
    _laneLength = _segmentLength * ARGON2_SYNC_POINTS;
    _memoryBlocks = _laneLength * parameters.lanes;
    _memory = Uint64List(_memoryBlocks * _q);
  }

  /// Derives [outLen] bytes (default: the rest of [out]) from [password] into
  /// [out] at [outOff]. Returns the number of bytes written.
  int generateBytes(Uint8List password, Uint8List out,
      [int outOff = 0, int? outLen]) {
    outLen ??= out.length - outOff;

    if (outLen < MIN_OUTLEN) {
      throw ArgumentError.value(
          outLen, 'outLen', 'output length less than $MIN_OUTLEN');
    }

    final tmpBlockBytes = Uint8List(ARGON2_BLOCK_SIZE);

    _initialize(tmpBlockBytes, password, outLen);
    _fillMemoryBlocks();
    _digest(tmpBlockBytes, out, outOff, outLen);

    // Wipe: the memory is a function of the password.
    _memory.fillRange(0, _memory.length, 0);
    _z.fillRange(0, _q, 0);
    _addressBlock.fillRange(0, _q, 0);
    _inputBlock.fillRange(0, _q, 0);

    return outLen;
  }

  // ---------------------------------------------------------------------------
  // Memory filling
  // ---------------------------------------------------------------------------

  void _fillMemoryBlocks() {
    final lanes = _parameters.lanes;
    for (var pass = 0; pass < _parameters.iterations; ++pass) {
      for (var slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
        for (var lane = 0; lane < lanes; ++lane) {
          _fillSegment(pass, slice, lane);
        }
      }
    }
  }

  void _fillSegment(int pass, int slice, int lane) {
    final type = _parameters.type;
    final lanes = _parameters.lanes;
    final memory = _memory;
    final addressBlock = _addressBlock;

    final dataIndependentAddressing = type == Argon2Parameters.ARGON2_i ||
        (type == Argon2Parameters.ARGON2_id &&
            pass == 0 &&
            slice < ARGON2_SYNC_POINTS ~/ 2);
    final withXor =
        pass != 0 && _parameters.version != Argon2Parameters.ARGON2_VERSION_10;

    // The first two blocks of every lane come from the initial hash.
    final startingIndex = (pass == 0 && slice == 0) ? 2 : 0;

    if (dataIndependentAddressing) {
      final input = _inputBlock..fillRange(0, _q, 0);
      input[0] = pass;
      input[1] = lane;
      input[2] = slice;
      input[3] = _memoryBlocks;
      input[4] = _parameters.iterations;
      input[5] = type;
      // Index 0 of this segment was skipped, so generate its addresses here.
      if (startingIndex == 2) _nextAddresses();
    }

    var currentOffset =
        lane * _laneLength + slice * _segmentLength + startingIndex;
    var prevOffset = currentOffset % _laneLength == 0
        ? currentOffset + _laneLength - 1
        : currentOffset - 1;

    for (var index = startingIndex; index < _segmentLength; ++index) {
      int pseudoRandom;
      if (dataIndependentAddressing) {
        final addressIndex = index % ARGON2_ADDRESSES_IN_BLOCK;
        if (addressIndex == 0) _nextAddresses();
        pseudoRandom = addressBlock[addressIndex];
      } else {
        pseudoRandom = memory[prevOffset * _q];
      }

      var refLane = (pseudoRandom >>> 32) % lanes;
      if (pass == 0 && slice == 0) refLane = lane;

      final refColumn = _referenceIndex(
          pass, slice, index, pseudoRandom & _m32, refLane == lane);

      _fillBlock(
        memory,
        prevOffset * _q,
        memory,
        (refLane * _laneLength + refColumn) * _q,
        memory,
        currentOffset * _q,
        withXor,
      );

      prevOffset = currentOffset;
      currentOffset++;
    }
  }

  /// Argon2i addressing: the next 128 pseudo-random words come from
  /// `G(0, G(0, input))`, with the counter in `input[6]` bumped first.
  void _nextAddresses() {
    _inputBlock[6] = _inputBlock[6] + 1;
    _fillBlock(_zeroBlock, 0, _inputBlock, 0, _addressBlock, 0, false);
    _fillBlock(_zeroBlock, 0, _addressBlock, 0, _addressBlock, 0, false);
  }

  /// RFC 9106, section 3.4.2: maps the 32-bit [j1] onto the reference area
  /// the block at [index] of the current segment is allowed to read from.
  int _referenceIndex(int pass, int slice, int index, int j1, bool sameLane) {
    int referenceAreaSize;
    int startPosition;

    if (pass == 0) {
      startPosition = 0;
      if (sameLane) {
        referenceAreaSize = slice * _segmentLength + index - 1;
      } else {
        referenceAreaSize = slice * _segmentLength + (index == 0 ? -1 : 0);
      }
    } else {
      startPosition = ((slice + 1) * _segmentLength) % _laneLength;
      if (sameLane) {
        referenceAreaSize = _laneLength - _segmentLength + index - 1;
      } else {
        referenceAreaSize =
            _laneLength - _segmentLength + (index == 0 ? -1 : 0);
      }
    }

    // Both products are of two 32-bit values, so they fit in 64 bits; `>>>`
    // reads the wrapped result as unsigned.
    var relativePosition = (j1 * j1) >>> 32;
    relativePosition =
        referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >>> 32);

    return (startPosition + relativePosition) % _laneLength;
  }

  // ---------------------------------------------------------------------------
  // Compression function G
  // ---------------------------------------------------------------------------

  /// `next = X ^ Y ^ P(X ^ Y)`, or `next ^= ...` when [withXor], where X is
  /// the block at [xo] of [x] and Y the block at [yo] of [y]. Buffers may
  /// alias ([y] and [next] do for the address blocks): each word of `next` is
  /// read, if at all, before it is written.
  void _fillBlock(Uint64List x, int xo, Uint64List y, int yo, Uint64List next,
      int no, bool withXor) {
    final z = _z;
    for (var i = 0; i < _q; i++) {
      z[i] = x[xo + i] ^ y[yo + i];
    }

    for (var i = 0; i < 8; i++) {
      _permuteRow(z, i * 16);
    }
    for (var i = 0; i < 8; i++) {
      _permuteColumn(z, i * 2);
    }

    if (withXor) {
      for (var i = 0; i < _q; i++) {
        next[no + i] ^= x[xo + i] ^ y[yo + i] ^ z[i];
      }
    } else {
      for (var i = 0; i < _q; i++) {
        next[no + i] = x[xo + i] ^ y[yo + i] ^ z[i];
      }
    }
  }

  // The two functions below are the BLAKE2b round with the Argon2 addition
  // `a + b + 2 * lo32(a) * lo32(b)`, applied to 16 words held in locals. They
  // were generated: eight G steps over (v0, v4, v8, v12), (v1, v5, v9, v13),
  // (v2, v6, v10, v14), (v3, v7, v11, v15), (v0, v5, v10, v15),
  // (v1, v6, v11, v12), (v2, v7, v8, v13), (v3, v4, v9, v14), each G being
  //
  //   a = a + b + 2 * lo32(a) * lo32(b);  d = rotr64(d ^ a, 32);
  //   c = c + d + 2 * lo32(c) * lo32(d);  b = rotr64(b ^ c, 24);
  //   a = a + b + 2 * lo32(a) * lo32(b);  d = rotr64(d ^ a, 16);
  //   c = c + d + 2 * lo32(c) * lo32(d);  b = rotr64(b ^ c, 63);
  //
  // with the multiply written as `((lo32(a) | _hi) * lo32(b)) << 1`, see [_hi].

  /// P over the 16 consecutive words starting at [o] (a row of the 8x16 matrix).
  static void _permuteRow(Uint64List z, int o) {
    var v0 = z[o];
    var v1 = z[o + 1];
    var v2 = z[o + 2];
    var v3 = z[o + 3];
    var v4 = z[o + 4];
    var v5 = z[o + 5];
    var v6 = z[o + 6];
    var v7 = z[o + 7];
    var v8 = z[o + 8];
    var v9 = z[o + 9];
    var v10 = z[o + 10];
    var v11 = z[o + 11];
    var v12 = z[o + 12];
    var v13 = z[o + 13];
    var v14 = z[o + 14];
    var v15 = z[o + 15];

    v0 = v0 + v4 + ((((v0 & _m32) | _hi) * (v4 & _m32)) << 1);
    v12 ^= v0;
    v12 = (v12 >>> 32) | (v12 << 32);
    v8 = v8 + v12 + ((((v8 & _m32) | _hi) * (v12 & _m32)) << 1);
    v4 ^= v8;
    v4 = (v4 >>> 24) | (v4 << 40);
    v0 = v0 + v4 + ((((v0 & _m32) | _hi) * (v4 & _m32)) << 1);
    v12 ^= v0;
    v12 = (v12 >>> 16) | (v12 << 48);
    v8 = v8 + v12 + ((((v8 & _m32) | _hi) * (v12 & _m32)) << 1);
    v4 ^= v8;
    v4 = (v4 >>> 63) | (v4 << 1);

    v1 = v1 + v5 + ((((v1 & _m32) | _hi) * (v5 & _m32)) << 1);
    v13 ^= v1;
    v13 = (v13 >>> 32) | (v13 << 32);
    v9 = v9 + v13 + ((((v9 & _m32) | _hi) * (v13 & _m32)) << 1);
    v5 ^= v9;
    v5 = (v5 >>> 24) | (v5 << 40);
    v1 = v1 + v5 + ((((v1 & _m32) | _hi) * (v5 & _m32)) << 1);
    v13 ^= v1;
    v13 = (v13 >>> 16) | (v13 << 48);
    v9 = v9 + v13 + ((((v9 & _m32) | _hi) * (v13 & _m32)) << 1);
    v5 ^= v9;
    v5 = (v5 >>> 63) | (v5 << 1);

    v2 = v2 + v6 + ((((v2 & _m32) | _hi) * (v6 & _m32)) << 1);
    v14 ^= v2;
    v14 = (v14 >>> 32) | (v14 << 32);
    v10 = v10 + v14 + ((((v10 & _m32) | _hi) * (v14 & _m32)) << 1);
    v6 ^= v10;
    v6 = (v6 >>> 24) | (v6 << 40);
    v2 = v2 + v6 + ((((v2 & _m32) | _hi) * (v6 & _m32)) << 1);
    v14 ^= v2;
    v14 = (v14 >>> 16) | (v14 << 48);
    v10 = v10 + v14 + ((((v10 & _m32) | _hi) * (v14 & _m32)) << 1);
    v6 ^= v10;
    v6 = (v6 >>> 63) | (v6 << 1);

    v3 = v3 + v7 + ((((v3 & _m32) | _hi) * (v7 & _m32)) << 1);
    v15 ^= v3;
    v15 = (v15 >>> 32) | (v15 << 32);
    v11 = v11 + v15 + ((((v11 & _m32) | _hi) * (v15 & _m32)) << 1);
    v7 ^= v11;
    v7 = (v7 >>> 24) | (v7 << 40);
    v3 = v3 + v7 + ((((v3 & _m32) | _hi) * (v7 & _m32)) << 1);
    v15 ^= v3;
    v15 = (v15 >>> 16) | (v15 << 48);
    v11 = v11 + v15 + ((((v11 & _m32) | _hi) * (v15 & _m32)) << 1);
    v7 ^= v11;
    v7 = (v7 >>> 63) | (v7 << 1);

    v0 = v0 + v5 + ((((v0 & _m32) | _hi) * (v5 & _m32)) << 1);
    v15 ^= v0;
    v15 = (v15 >>> 32) | (v15 << 32);
    v10 = v10 + v15 + ((((v10 & _m32) | _hi) * (v15 & _m32)) << 1);
    v5 ^= v10;
    v5 = (v5 >>> 24) | (v5 << 40);
    v0 = v0 + v5 + ((((v0 & _m32) | _hi) * (v5 & _m32)) << 1);
    v15 ^= v0;
    v15 = (v15 >>> 16) | (v15 << 48);
    v10 = v10 + v15 + ((((v10 & _m32) | _hi) * (v15 & _m32)) << 1);
    v5 ^= v10;
    v5 = (v5 >>> 63) | (v5 << 1);

    v1 = v1 + v6 + ((((v1 & _m32) | _hi) * (v6 & _m32)) << 1);
    v12 ^= v1;
    v12 = (v12 >>> 32) | (v12 << 32);
    v11 = v11 + v12 + ((((v11 & _m32) | _hi) * (v12 & _m32)) << 1);
    v6 ^= v11;
    v6 = (v6 >>> 24) | (v6 << 40);
    v1 = v1 + v6 + ((((v1 & _m32) | _hi) * (v6 & _m32)) << 1);
    v12 ^= v1;
    v12 = (v12 >>> 16) | (v12 << 48);
    v11 = v11 + v12 + ((((v11 & _m32) | _hi) * (v12 & _m32)) << 1);
    v6 ^= v11;
    v6 = (v6 >>> 63) | (v6 << 1);

    v2 = v2 + v7 + ((((v2 & _m32) | _hi) * (v7 & _m32)) << 1);
    v13 ^= v2;
    v13 = (v13 >>> 32) | (v13 << 32);
    v8 = v8 + v13 + ((((v8 & _m32) | _hi) * (v13 & _m32)) << 1);
    v7 ^= v8;
    v7 = (v7 >>> 24) | (v7 << 40);
    v2 = v2 + v7 + ((((v2 & _m32) | _hi) * (v7 & _m32)) << 1);
    v13 ^= v2;
    v13 = (v13 >>> 16) | (v13 << 48);
    v8 = v8 + v13 + ((((v8 & _m32) | _hi) * (v13 & _m32)) << 1);
    v7 ^= v8;
    v7 = (v7 >>> 63) | (v7 << 1);

    v3 = v3 + v4 + ((((v3 & _m32) | _hi) * (v4 & _m32)) << 1);
    v14 ^= v3;
    v14 = (v14 >>> 32) | (v14 << 32);
    v9 = v9 + v14 + ((((v9 & _m32) | _hi) * (v14 & _m32)) << 1);
    v4 ^= v9;
    v4 = (v4 >>> 24) | (v4 << 40);
    v3 = v3 + v4 + ((((v3 & _m32) | _hi) * (v4 & _m32)) << 1);
    v14 ^= v3;
    v14 = (v14 >>> 16) | (v14 << 48);
    v9 = v9 + v14 + ((((v9 & _m32) | _hi) * (v14 & _m32)) << 1);
    v4 ^= v9;
    v4 = (v4 >>> 63) | (v4 << 1);

    z[o] = v0;
    z[o + 1] = v1;
    z[o + 2] = v2;
    z[o + 3] = v3;
    z[o + 4] = v4;
    z[o + 5] = v5;
    z[o + 6] = v6;
    z[o + 7] = v7;
    z[o + 8] = v8;
    z[o + 9] = v9;
    z[o + 10] = v10;
    z[o + 11] = v11;
    z[o + 12] = v12;
    z[o + 13] = v13;
    z[o + 14] = v14;
    z[o + 15] = v15;
  }

  /// P over the 16 words at [o] + {0, 1, 16, 17, ..., 112, 113} (a column of the matrix, two words per row).
  static void _permuteColumn(Uint64List z, int o) {
    var v0 = z[o];
    var v1 = z[o + 1];
    var v2 = z[o + 16];
    var v3 = z[o + 17];
    var v4 = z[o + 32];
    var v5 = z[o + 33];
    var v6 = z[o + 48];
    var v7 = z[o + 49];
    var v8 = z[o + 64];
    var v9 = z[o + 65];
    var v10 = z[o + 80];
    var v11 = z[o + 81];
    var v12 = z[o + 96];
    var v13 = z[o + 97];
    var v14 = z[o + 112];
    var v15 = z[o + 113];

    v0 = v0 + v4 + ((((v0 & _m32) | _hi) * (v4 & _m32)) << 1);
    v12 ^= v0;
    v12 = (v12 >>> 32) | (v12 << 32);
    v8 = v8 + v12 + ((((v8 & _m32) | _hi) * (v12 & _m32)) << 1);
    v4 ^= v8;
    v4 = (v4 >>> 24) | (v4 << 40);
    v0 = v0 + v4 + ((((v0 & _m32) | _hi) * (v4 & _m32)) << 1);
    v12 ^= v0;
    v12 = (v12 >>> 16) | (v12 << 48);
    v8 = v8 + v12 + ((((v8 & _m32) | _hi) * (v12 & _m32)) << 1);
    v4 ^= v8;
    v4 = (v4 >>> 63) | (v4 << 1);

    v1 = v1 + v5 + ((((v1 & _m32) | _hi) * (v5 & _m32)) << 1);
    v13 ^= v1;
    v13 = (v13 >>> 32) | (v13 << 32);
    v9 = v9 + v13 + ((((v9 & _m32) | _hi) * (v13 & _m32)) << 1);
    v5 ^= v9;
    v5 = (v5 >>> 24) | (v5 << 40);
    v1 = v1 + v5 + ((((v1 & _m32) | _hi) * (v5 & _m32)) << 1);
    v13 ^= v1;
    v13 = (v13 >>> 16) | (v13 << 48);
    v9 = v9 + v13 + ((((v9 & _m32) | _hi) * (v13 & _m32)) << 1);
    v5 ^= v9;
    v5 = (v5 >>> 63) | (v5 << 1);

    v2 = v2 + v6 + ((((v2 & _m32) | _hi) * (v6 & _m32)) << 1);
    v14 ^= v2;
    v14 = (v14 >>> 32) | (v14 << 32);
    v10 = v10 + v14 + ((((v10 & _m32) | _hi) * (v14 & _m32)) << 1);
    v6 ^= v10;
    v6 = (v6 >>> 24) | (v6 << 40);
    v2 = v2 + v6 + ((((v2 & _m32) | _hi) * (v6 & _m32)) << 1);
    v14 ^= v2;
    v14 = (v14 >>> 16) | (v14 << 48);
    v10 = v10 + v14 + ((((v10 & _m32) | _hi) * (v14 & _m32)) << 1);
    v6 ^= v10;
    v6 = (v6 >>> 63) | (v6 << 1);

    v3 = v3 + v7 + ((((v3 & _m32) | _hi) * (v7 & _m32)) << 1);
    v15 ^= v3;
    v15 = (v15 >>> 32) | (v15 << 32);
    v11 = v11 + v15 + ((((v11 & _m32) | _hi) * (v15 & _m32)) << 1);
    v7 ^= v11;
    v7 = (v7 >>> 24) | (v7 << 40);
    v3 = v3 + v7 + ((((v3 & _m32) | _hi) * (v7 & _m32)) << 1);
    v15 ^= v3;
    v15 = (v15 >>> 16) | (v15 << 48);
    v11 = v11 + v15 + ((((v11 & _m32) | _hi) * (v15 & _m32)) << 1);
    v7 ^= v11;
    v7 = (v7 >>> 63) | (v7 << 1);

    v0 = v0 + v5 + ((((v0 & _m32) | _hi) * (v5 & _m32)) << 1);
    v15 ^= v0;
    v15 = (v15 >>> 32) | (v15 << 32);
    v10 = v10 + v15 + ((((v10 & _m32) | _hi) * (v15 & _m32)) << 1);
    v5 ^= v10;
    v5 = (v5 >>> 24) | (v5 << 40);
    v0 = v0 + v5 + ((((v0 & _m32) | _hi) * (v5 & _m32)) << 1);
    v15 ^= v0;
    v15 = (v15 >>> 16) | (v15 << 48);
    v10 = v10 + v15 + ((((v10 & _m32) | _hi) * (v15 & _m32)) << 1);
    v5 ^= v10;
    v5 = (v5 >>> 63) | (v5 << 1);

    v1 = v1 + v6 + ((((v1 & _m32) | _hi) * (v6 & _m32)) << 1);
    v12 ^= v1;
    v12 = (v12 >>> 32) | (v12 << 32);
    v11 = v11 + v12 + ((((v11 & _m32) | _hi) * (v12 & _m32)) << 1);
    v6 ^= v11;
    v6 = (v6 >>> 24) | (v6 << 40);
    v1 = v1 + v6 + ((((v1 & _m32) | _hi) * (v6 & _m32)) << 1);
    v12 ^= v1;
    v12 = (v12 >>> 16) | (v12 << 48);
    v11 = v11 + v12 + ((((v11 & _m32) | _hi) * (v12 & _m32)) << 1);
    v6 ^= v11;
    v6 = (v6 >>> 63) | (v6 << 1);

    v2 = v2 + v7 + ((((v2 & _m32) | _hi) * (v7 & _m32)) << 1);
    v13 ^= v2;
    v13 = (v13 >>> 32) | (v13 << 32);
    v8 = v8 + v13 + ((((v8 & _m32) | _hi) * (v13 & _m32)) << 1);
    v7 ^= v8;
    v7 = (v7 >>> 24) | (v7 << 40);
    v2 = v2 + v7 + ((((v2 & _m32) | _hi) * (v7 & _m32)) << 1);
    v13 ^= v2;
    v13 = (v13 >>> 16) | (v13 << 48);
    v8 = v8 + v13 + ((((v8 & _m32) | _hi) * (v13 & _m32)) << 1);
    v7 ^= v8;
    v7 = (v7 >>> 63) | (v7 << 1);

    v3 = v3 + v4 + ((((v3 & _m32) | _hi) * (v4 & _m32)) << 1);
    v14 ^= v3;
    v14 = (v14 >>> 32) | (v14 << 32);
    v9 = v9 + v14 + ((((v9 & _m32) | _hi) * (v14 & _m32)) << 1);
    v4 ^= v9;
    v4 = (v4 >>> 24) | (v4 << 40);
    v3 = v3 + v4 + ((((v3 & _m32) | _hi) * (v4 & _m32)) << 1);
    v14 ^= v3;
    v14 = (v14 >>> 16) | (v14 << 48);
    v9 = v9 + v14 + ((((v9 & _m32) | _hi) * (v14 & _m32)) << 1);
    v4 ^= v9;
    v4 = (v4 >>> 63) | (v4 << 1);

    z[o] = v0;
    z[o + 1] = v1;
    z[o + 16] = v2;
    z[o + 17] = v3;
    z[o + 32] = v4;
    z[o + 33] = v5;
    z[o + 48] = v6;
    z[o + 49] = v7;
    z[o + 64] = v8;
    z[o + 65] = v9;
    z[o + 80] = v10;
    z[o + 81] = v11;
    z[o + 96] = v12;
    z[o + 97] = v13;
    z[o + 112] = v14;
    z[o + 113] = v15;
  }

  // ---------------------------------------------------------------------------
  // Initial hash and final digest
  // ---------------------------------------------------------------------------

  void _initialize(
      Uint8List tmpBlockBytes, Uint8List password, int outputLength) {
    final blake = _Blake2b(ARGON2_PREHASH_DIGEST_LENGTH);

    final header = ByteData(24)
      ..setUint32(0, _parameters.lanes, Endian.little)
      ..setUint32(4, outputLength, Endian.little)
      ..setUint32(8, _parameters.memory, Endian.little)
      ..setUint32(12, _parameters.iterations, Endian.little)
      ..setUint32(16, _parameters.version, Endian.little)
      ..setUint32(20, _parameters.type, Endian.little);
    blake.update(header.buffer.asUint8List(), 0, 24);

    _addByteString(blake, password);
    _addByteString(blake, _parameters.salt);
    _addByteString(blake, _parameters.secret);
    _addByteString(blake, _parameters.additional);

    // H0 followed by room for LE32(block index) and LE32(lane).
    final initialHashWithZeros = Uint8List(ARGON2_PREHASH_SEED_LENGTH);
    blake.doFinal(initialHashWithZeros, 0);

    _fillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
  }

  static void _addByteString(_Blake2b digest, Uint8List? octets) {
    final length = Uint8List(4);
    ByteData.view(length.buffer)
        .setUint32(0, octets?.length ?? 0, Endian.little);
    digest.update(length, 0, 4);
    if (octets != null && octets.isNotEmpty) {
      digest.update(octets, 0, octets.length);
    }
  }

  void _fillFirstBlocks(
      Uint8List tmpBlockBytes, Uint8List initialHashWithZeros) {
    final initialHashWithOnes = Uint8List(ARGON2_PREHASH_SEED_LENGTH)
      ..setRange(0, ARGON2_PREHASH_DIGEST_LENGTH, initialHashWithZeros);
    initialHashWithOnes[ARGON2_PREHASH_DIGEST_LENGTH] = 1;

    final zeros = ByteData.view(initialHashWithZeros.buffer);
    final ones = ByteData.view(initialHashWithOnes.buffer);

    for (var lane = 0; lane < _parameters.lanes; lane++) {
      zeros.setUint32(ARGON2_PREHASH_DIGEST_LENGTH + 4, lane, Endian.little);
      ones.setUint32(ARGON2_PREHASH_DIGEST_LENGTH + 4, lane, Endian.little);

      _hash(initialHashWithZeros, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
      _bytesToBlock(tmpBlockBytes, lane * _laneLength);

      _hash(initialHashWithOnes, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
      _bytesToBlock(tmpBlockBytes, lane * _laneLength + 1);
    }
  }

  void _digest(Uint8List tmpBlockBytes, Uint8List out, int outOff, int outLen) {
    final memory = _memory;
    final finalOffset = (_laneLength - 1) * _q;

    for (var lane = 1; lane < _parameters.lanes; lane++) {
      final laneOffset = (lane * _laneLength + _laneLength - 1) * _q;
      for (var i = 0; i < _q; i++) {
        memory[finalOffset + i] ^= memory[laneOffset + i];
      }
    }

    _blockToBytes(_laneLength - 1, tmpBlockBytes);
    _hash(tmpBlockBytes, out, outOff, outLen);
  }

  void _bytesToBlock(Uint8List input, int block) {
    final data =
        ByteData.view(input.buffer, input.offsetInBytes, ARGON2_BLOCK_SIZE);
    final base = block * _q;
    for (var i = 0; i < _q; i++) {
      _memory[base + i] = data.getUint64(i * 8, Endian.little);
    }
  }

  void _blockToBytes(int block, Uint8List output) {
    final data =
        ByteData.view(output.buffer, output.offsetInBytes, ARGON2_BLOCK_SIZE);
    final base = block * _q;
    for (var i = 0; i < _q; i++) {
      data.setUint64(i * 8, _memory[base + i], Endian.little);
    }
  }

  /// The variable-length hash H' of RFC 9106, section 3.3.
  static void _hash(Uint8List input, Uint8List out, int outOff, int outLen) {
    final outLenBytes = Uint8List(4);
    ByteData.view(outLenBytes.buffer).setUint32(0, outLen, Endian.little);

    const blake2bLength = 64;

    if (outLen <= blake2bLength) {
      final blake = _Blake2b(outLen);
      blake.update(outLenBytes, 0, 4);
      blake.update(input, 0, input.length);
      blake.doFinal(out, outOff);
      return;
    }

    var digest = _Blake2b(blake2bLength);
    final outBuffer = Uint8List(blake2bLength);

    digest.update(outLenBytes, 0, 4);
    digest.update(input, 0, input.length);
    digest.doFinal(outBuffer, 0);

    const halfLen = blake2bLength ~/ 2;
    var outPos = outOff;
    out.setRange(outPos, outPos + halfLen, outBuffer);
    outPos += halfLen;

    final r = ((outLen + 31) ~/ 32) - 2;

    for (var i = 2; i <= r; i++, outPos += halfLen) {
      digest.update(outBuffer, 0, blake2bLength);
      digest.doFinal(outBuffer, 0);
      out.setRange(outPos, outPos + halfLen, outBuffer);
    }

    final lastLength = outLen - 32 * r;
    digest = _Blake2b(lastLength);
    digest.update(outBuffer, 0, blake2bLength);
    digest.doFinal(out, outPos);
  }
}

// ============================================================================
// BLAKE2B
// ============================================================================

/// BLAKE2b (RFC 7693) with a 1..64-byte digest and no key, on native 64-bit
/// words. Only used for the initial hash, the first two blocks of each lane
/// and the final tag, so it is written for clarity rather than speed.
class _Blake2b {
  static const int _blockSize = 128;

  // Hex literals above 2^63 are read as their two's-complement value.
  static const List<int> _iv = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
  ];

  static const List<int> _sigma = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, //
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, //
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, //
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, //
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, //
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, //
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, //
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, //
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0, //
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, //
  ];

  final int digestSize;
  final Uint8List _buffer = Uint8List(_blockSize);
  final Uint64List _h = Uint64List(8);
  final Uint64List _m = Uint64List(16);
  final Uint64List _v = Uint64List(16);
  int _bufferPos = 0;

  /// Bytes compressed so far. Inputs here are a few KiB, so the high word of
  /// the 128-bit counter is always zero.
  int _counter = 0;

  _Blake2b(this.digestSize) {
    if (digestSize < 1 || digestSize > 64) {
      throw ArgumentError.value(digestSize, 'digestSize',
          'BLAKE2b digest size must be between 1 and 64 bytes');
    }
    reset();
  }

  void reset() {
    for (var i = 0; i < 8; i++) {
      _h[i] = _iv[i];
    }
    _h[0] ^= 0x01010000 ^ digestSize;
    _buffer.fillRange(0, _blockSize, 0);
    _bufferPos = 0;
    _counter = 0;
  }

  void update(Uint8List input, int offset, int length) {
    var inputOffset = offset;
    var remaining = length;

    while (remaining > 0) {
      // A full buffer is only compressed once more input arrives, so the
      // last block is always the one finalised in [doFinal].
      if (_bufferPos == _blockSize) {
        _counter += _blockSize;
        _compress(false);
        _bufferPos = 0;
      }

      final free = _blockSize - _bufferPos;
      final toCopy = free < remaining ? free : remaining;
      _buffer.setRange(_bufferPos, _bufferPos + toCopy, input, inputOffset);
      _bufferPos += toCopy;
      inputOffset += toCopy;
      remaining -= toCopy;
    }
  }

  int doFinal(Uint8List out, int outOff) {
    _counter += _bufferPos;
    _buffer.fillRange(_bufferPos, _blockSize, 0);
    _compress(true);

    final digest = ByteData(64);
    for (var i = 0; i < 8; i++) {
      digest.setUint64(i * 8, _h[i], Endian.little);
    }
    out.setRange(outOff, outOff + digestSize, digest.buffer.asUint8List());

    reset();
    return digestSize;
  }

  void _compress(bool isLastBlock) {
    final m = _m;
    final v = _v;
    final h = _h;

    final block = ByteData.view(_buffer.buffer);
    for (var i = 0; i < 16; i++) {
      m[i] = block.getUint64(i * 8, Endian.little);
    }
    for (var i = 0; i < 8; i++) {
      v[i] = h[i];
      v[i + 8] = _iv[i];
    }

    v[12] ^= _counter;
    // v[13] ^= high word of the counter, which is always zero here.
    if (isLastBlock) v[14] = ~v[14];

    for (var round = 0; round < 12; round++) {
      final s = round * 16;
      _g(v, 0, 4, 8, 12, m[_sigma[s]], m[_sigma[s + 1]]);
      _g(v, 1, 5, 9, 13, m[_sigma[s + 2]], m[_sigma[s + 3]]);
      _g(v, 2, 6, 10, 14, m[_sigma[s + 4]], m[_sigma[s + 5]]);
      _g(v, 3, 7, 11, 15, m[_sigma[s + 6]], m[_sigma[s + 7]]);
      _g(v, 0, 5, 10, 15, m[_sigma[s + 8]], m[_sigma[s + 9]]);
      _g(v, 1, 6, 11, 12, m[_sigma[s + 10]], m[_sigma[s + 11]]);
      _g(v, 2, 7, 8, 13, m[_sigma[s + 12]], m[_sigma[s + 13]]);
      _g(v, 3, 4, 9, 14, m[_sigma[s + 14]], m[_sigma[s + 15]]);
    }

    for (var i = 0; i < 8; i++) {
      h[i] ^= v[i] ^ v[i + 8];
    }
  }

  static void _g(Uint64List v, int a, int b, int c, int d, int x, int y) {
    var va = v[a];
    var vb = v[b];
    var vc = v[c];
    var vd = v[d];

    va = va + vb + x;
    vd ^= va;
    vd = (vd >>> 32) | (vd << 32);
    vc = vc + vd;
    vb ^= vc;
    vb = (vb >>> 24) | (vb << 40);
    va = va + vb + y;
    vd ^= va;
    vd = (vd >>> 16) | (vd << 48);
    vc = vc + vd;
    vb ^= vc;
    vb = (vb >>> 63) | (vb << 1);

    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
  }
}
