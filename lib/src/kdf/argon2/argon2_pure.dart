// Pure Dart Argon2 (Argon2d / Argon2i / Argon2id), RFC 9106.
//
// Vendored from the SALI core package
// (core/lib/dependencies/argon2/implementation/argon2_pure.dart), which in turn
// follows the Bouncy Castle reference implementation. Kept self-contained on
// purpose: no dependency beyond dart:typed_data, so it also works where the
// loaded libcrypto predates OpenSSL 3.2 and has no native Argon2.
//
// Prefer the [Argon2] facade in ../argon2.dart: it uses OpenSSL's native
// implementation when available and falls back to this one otherwise.
//
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: camel_case_types, public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

// ============================================================================
// EXTENSIONS
// ============================================================================

extension ListExtension<T> on List<T> {
  List<T> copy() => List<T>.from(this);

  void setFrom(int startIndex, List<T> from, int fromIndex, int length) {
    for (var i = 0; i < length; ++i) {
      this[startIndex + i] = from[fromIndex + i];
    }
  }
}

extension ListIntExtension on List<int> {
  Uint8List copy() => Uint8List.fromList(this);

  Uint8List toUint8List() =>
      this is Uint8List ? this as Uint8List : Uint8List.fromList(this);

  void clear() => setAllElementsTo(0);

  void setAllElementsTo(int value) {
    for (var i = length - 1; i >= 0; --i) {
      this[i] = value;
    }
  }
}

extension StringExtension on String {
  Uint8List toBytesUTF8() => utf8.encode(this).toUint8List();

  Uint8List toBytesLatin1() => latin1.encode(this);
}

extension Uint8ListExtension on Uint8List {
  ByteData get asByteData => ByteData.view(buffer, offsetInBytes, lengthInBytes);

  void reset() => setAllElementsTo(0);

  String toHexString() {
    final buffer = StringBuffer();
    for (final byte in this) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

// ============================================================================
// UTILS / PACK (JS-Safe)
// ============================================================================

abstract class Pack {
  static void littleEndianToLongAtList(Uint8List bs, int off, Uint32List ns) {
    var data = ByteData.view(bs.buffer, bs.offsetInBytes, bs.lengthInBytes);
    for (var i = 0; i < ns.length; i += 2) {
      // Little Endian: parte baixa primeiro (emulando 64-bits com dois 32-bits)
      ns[i] = data.getUint32(off, Endian.little);
      ns[i + 1] = data.getUint32(off + 4, Endian.little);
      off += 8;
    }
  }

  static void longListToLittleEndianAtList(Uint32List ns, Uint8List bs, int off) {
    var data = ByteData.view(bs.buffer, bs.offsetInBytes, bs.lengthInBytes);
    for (var i = 0; i < ns.length; i += 2) {
      data.setUint32(off, ns[i], Endian.little);
      data.setUint32(off + 4, ns[i + 1], Endian.little);
      off += 8;
    }
  }

  static void intToLittleEndianAtList(int n, Uint8List bs, int off) {
    var data = bs.asByteData;
    data.setInt32(off, n, Endian.little);
  }

  static void intListToLittleEndianAtList(Uint32List ns, Uint8List bs, int off) {
    for (var i = 0; i < ns.length; ++i) {
      intToLittleEndianAtList(ns[i], bs, off);
      off += 4;
    }
  }
}

// ============================================================================
// PARAMETERS
// ============================================================================

abstract class CharToByteConverter {
  static const UTF8 = CharToByteConverterUTF8();
  static const ASCII = CharToByteConverterASCII();

  String get name;
  Uint8List convert(String password);
}

class CharToByteConverterUTF8 implements CharToByteConverter {
  const CharToByteConverterUTF8();
  @override
  String get name => 'UTF8';
  @override
  Uint8List convert(String password) => utf8.encode(password).toUint8List();
}

class CharToByteConverterASCII implements CharToByteConverter {
  const CharToByteConverterASCII();
  @override
  String get name => 'ASCII';
  @override
  Uint8List convert(String password) => latin1.encode(password).toUint8List();
}

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
  final Uint8List _salt;
  final Uint8List? _secret;
  final Uint8List? _additional;

  final int iterations;
  final int memory;
  final int lanes;
  final int version;
  final CharToByteConverter converter;

  Argon2Parameters(
    this.type,
    this._salt, {
    Uint8List? secret,
    Uint8List? additional,
    this.iterations = DEFAULT_ITERATIONS,
    int? memoryPowerOf2,
    int? memory,
    this.lanes = DEFAULT_LANES,
    this.version = DEFAULT_VERSION,
    this.converter = CharToByteConverter.UTF8,
  })  : memory = memoryPowerOf2 != null
            ? 1 << memoryPowerOf2
            : (memory ?? (1 << DEFAULT_MEMORY_COST)),
        _secret = secret,
        _additional = additional;

  Uint8List get salt => _salt;
  Uint8List? get secret => _secret;
  Uint8List? get additional => _additional;

  void clear() {
    _salt.clear();
    _secret?.clear();
    _additional?.clear();
  }

  @override
  String toString() {
    return 'Argon2Parameters{ type: $type, iterations: $iterations, memory: $memory, lanes: $lanes, version: $version, converter: ${converter.name} }';
  }
}

// ============================================================================
// BLAKE2B DIGEST
// ============================================================================

class _Blake2bDigest {
  static const int _blockSize = 128;
  static final BigInt _mask64 = (BigInt.one << 64) - BigInt.one;
  static final List<BigInt> _iv = [
    BigInt.parse('6a09e667f3bcc908', radix: 16),
    BigInt.parse('bb67ae8584caa73b', radix: 16),
    BigInt.parse('3c6ef372fe94f82b', radix: 16),
    BigInt.parse('a54ff53a5f1d36f1', radix: 16),
    BigInt.parse('510e527fade682d1', radix: 16),
    BigInt.parse('9b05688c2b3e6c1f', radix: 16),
    BigInt.parse('1f83d9abfb41bd6b', radix: 16),
    BigInt.parse('5be0cd19137e2179', radix: 16),
  ];

  static const List<List<int>> _sigma = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  ];

  final int digestSize;
  final Uint8List _buffer = Uint8List(_blockSize);
  late List<BigInt> _h;
  int _bufferPos = 0;
  BigInt _counter = BigInt.zero;

  _Blake2bDigest({required this.digestSize}) {
    if (digestSize < 1 || digestSize > 64) {
      throw ArgumentError.value(digestSize, 'digestSize',
          'BLAKE2b digest size must be between 1 and 64 bytes');
    }
    reset();
  }

  void reset() {
    _h = List<BigInt>.from(_iv);
    _h[0] = _u64(_h[0] ^ BigInt.from(0x01010000 ^ digestSize));
    _buffer.fillRange(0, _buffer.length, 0);
    _bufferPos = 0;
    _counter = BigInt.zero;
  }

  void update(Uint8List input, int offset, int length) {
    var inputOffset = offset;
    var remaining = length;

    while (remaining > 0) {
      if (_bufferPos == _blockSize) {
        _counter += BigInt.from(_blockSize);
        _compress(_buffer, false);
        _bufferPos = 0;
      }

      final toCopy = (_blockSize - _bufferPos) < remaining
          ? (_blockSize - _bufferPos)
          : remaining;
      _buffer.setRange(
          _bufferPos, _bufferPos + toCopy, input, inputOffset);
      _bufferPos += toCopy;
      inputOffset += toCopy;
      remaining -= toCopy;
    }
  }

  int doFinal(Uint8List out, int outOff) {
    _counter += BigInt.from(_bufferPos);
    _buffer.fillRange(_bufferPos, _buffer.length, 0);
    _compress(_buffer, true);

    final fullDigest = Uint8List(64);
    for (var i = 0; i < _h.length; i++) {
      _writeUint64LittleEndian(_h[i], fullDigest, i * 8);
    }

    out.setRange(outOff, outOff + digestSize, fullDigest);
    reset();
    return digestSize;
  }

  void _compress(Uint8List block, bool isLastBlock) {
    final m = List<BigInt>.generate(
        16, (index) => _readUint64LittleEndian(block, index * 8));
    final v = <BigInt>[..._h, ..._iv];

    v[12] = _u64(v[12] ^ (_counter & _mask64));
    v[13] = _u64(v[13] ^ ((_counter >> 64) & _mask64));
    if (isLastBlock) {
      v[14] = _u64(v[14] ^ _mask64);
    }

    for (var round = 0; round < 12; round++) {
      final s = _sigma[round];
      _g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      _g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      _g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      _g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      _g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      _g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      _g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      _g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (var i = 0; i < _h.length; i++) {
      _h[i] = _u64(_h[i] ^ v[i] ^ v[i + 8]);
    }
  }

  static void _g(List<BigInt> v, int a, int b, int c, int d, BigInt x, BigInt y) {
    v[a] = _u64(v[a] + v[b] + x);
    v[d] = _rotr64(v[d] ^ v[a], 32);
    v[c] = _u64(v[c] + v[d]);
    v[b] = _rotr64(v[b] ^ v[c], 24);
    v[a] = _u64(v[a] + v[b] + y);
    v[d] = _rotr64(v[d] ^ v[a], 16);
    v[c] = _u64(v[c] + v[d]);
    v[b] = _rotr64(v[b] ^ v[c], 63);
  }

  static BigInt _rotr64(BigInt value, int shift) {
    final normalized = value & _mask64;
    return _u64((normalized >> shift) | (normalized << (64 - shift)));
  }

  static BigInt _u64(BigInt value) => value & _mask64;

  static BigInt _readUint64LittleEndian(Uint8List bytes, int offset) {
    var result = BigInt.zero;
    for (var i = 7; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[offset + i]);
    }
    return result;
  }

  static void _writeUint64LittleEndian(BigInt value, Uint8List bytes, int offset) {
    var current = value & _mask64;
    for (var i = 0; i < 8; i++) {
      bytes[offset + i] = (current & BigInt.from(0xff)).toInt();
      current >>= 8;
    }
  }
}

// ============================================================================
// ARGON2 CORE
// ============================================================================

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

  static final Uint8List _ZERO_BYTES = Uint8List(4);

  late Argon2Parameters _parameters;
  late List<_Block> _memory;
  late int _segmentLength;
  late int _laneLength;

  Argon2BytesGenerator();

  Argon2Parameters get parameters => _parameters;

  void init(Argon2Parameters parameters) {
    _parameters = parameters;

    if (parameters.lanes < Argon2BytesGenerator.MIN_PARALLELISM) {
      throw ArgumentError.value(parameters.lanes, 'parameters.lanes',
          'lanes must be greater than ${Argon2BytesGenerator.MIN_PARALLELISM}');
    } else if (parameters.lanes > Argon2BytesGenerator.MAX_PARALLELISM) {
      throw ArgumentError.value(parameters.lanes, 'parameters.lanes',
          'lanes must be less than ${Argon2BytesGenerator.MAX_PARALLELISM}');
    } else if (parameters.memory < 2 * parameters.lanes) {
      throw ArgumentError.value(parameters.memory, 'parameters.memory',
          'memory is less than: ${(2 * parameters.lanes)} expected ${(2 * parameters.lanes)}');
    } else if (parameters.iterations < Argon2BytesGenerator.MIN_ITERATIONS) {
      throw ArgumentError.value(parameters.iterations, 'parameters.iterations',
          'iterations is less than: ${Argon2BytesGenerator.MIN_ITERATIONS}');
    }

    _doInit(parameters);
  }

  int generateBytesFromString(String password, Uint8List out,
          [int outOff = 0, int? outLen]) =>
      generateBytes(_parameters.converter.convert(password), out, outOff, outLen);

  int generateBytes(Uint8List password, Uint8List out,
      [int outOff = 0, int? outLen]) {
    outLen ??= out.length;

    if (outLen < Argon2BytesGenerator.MIN_OUTLEN) {
      throw ArgumentError.value(outLen, 'outLen',
          'output length less than ${Argon2BytesGenerator.MIN_OUTLEN}');
    }

    var tmpBlockBytes = Uint8List(ARGON2_BLOCK_SIZE);

    _initialize(tmpBlockBytes, password, outLen);
    _fillMemoryBlocks();
    _digest(tmpBlockBytes, out, outOff, outLen);

    _reset();

    return outLen;
  }

  void _reset() {
    for (var i = _memory.length - 1; i >= 0; --i) {
      var b = _memory[i];
      b.clear();
    }
  }

  void _doInit(Argon2Parameters parameters) {
    var memoryBlocks = parameters.memory;

    if (memoryBlocks <
        2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.lanes) {
      memoryBlocks =
          2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.lanes;
    }

    _segmentLength = memoryBlocks ~/
        (parameters.lanes * Argon2BytesGenerator.ARGON2_SYNC_POINTS);
    _laneLength = _segmentLength * Argon2BytesGenerator.ARGON2_SYNC_POINTS;

    memoryBlocks = _segmentLength *
        (parameters.lanes * Argon2BytesGenerator.ARGON2_SYNC_POINTS);

    _initMemory(memoryBlocks);
  }

  void _initMemory(int memoryBlocks) {
    _memory = List<_Block>.generate(memoryBlocks, (i) => _Block());
  }

  void _fillMemoryBlocks() {
    var filler = _FillBlock();
    var position = _Position();
    for (var pass = 0; pass < _parameters.iterations; ++pass) {
      position.pass = pass;
      for (var slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
        position.slice = slice;
        for (var lane = 0; lane < _parameters.lanes; ++lane) {
          position.lane = lane;
          _fillSegment(filler, position);
        }
      }
    }
  }

  void _fillSegment(_FillBlock filler, _Position position) {
    _Block? addressBlock;
    _Block? inputBlock;

    var dataIndependentAddressing = _isDataIndependentAddressing(position);
    var startingIndex = _getStartingIndex(position);
    var currentOffset = position.lane * _laneLength +
        position.slice * _segmentLength +
        startingIndex;
    var prevOffset = _getPrevOffset(currentOffset);

    if (dataIndependentAddressing) {
      addressBlock = filler.addressBlock.clear();
      inputBlock = filler.inputBlock.clear();
      _initAddressBlocks(filler, position, inputBlock, addressBlock);
    }

    final withXor = _isWithXor(position);

    for (var index = startingIndex; index < _segmentLength; ++index) {
      var pseudoRandom = _getPseudoRandom(filler, index, addressBlock,
          inputBlock, prevOffset, dataIndependentAddressing);
      var refLane = _getRefLane(position, pseudoRandom.$2);
      var refColumn = _getRefColumn(
          position, index, pseudoRandom.$1, refLane == position.lane);

      var prevBlock = _memory[prevOffset];
      var refBlock = _memory[((_laneLength) * refLane + refColumn)];
      var currentBlock = _memory[currentOffset];

      if (withXor) {
        filler.fillBlockWithXor(prevBlock, refBlock, currentBlock);
      } else {
        filler.fillBlock2(prevBlock, refBlock, currentBlock);
      }

      prevOffset = currentOffset;
      currentOffset++;
    }
  }

  bool _isDataIndependentAddressing(_Position position) {
    return (_parameters.type == Argon2Parameters.ARGON2_i) ||
        (_parameters.type == Argon2Parameters.ARGON2_id &&
            (position.pass == 0) &&
            (position.slice < ARGON2_SYNC_POINTS / 2));
  }

  void _initAddressBlocks(_FillBlock filler, _Position position,
      _Block inputBlock, _Block addressBlock) {
    inputBlock._v[0] = position.pass;           inputBlock._v[1] = 0;
    inputBlock._v[2] = position.lane;           inputBlock._v[3] = 0;
    inputBlock._v[4] = position.slice;          inputBlock._v[5] = 0;
    inputBlock._v[6] = _memory.length;          inputBlock._v[7] = 0;
    inputBlock._v[8] = _parameters.iterations;  inputBlock._v[9] = 0;
    inputBlock._v[10] = _parameters.type;       inputBlock._v[11] = 0;
    inputBlock._v[12] = 0;                      inputBlock._v[13] = 0;

    if ((position.pass == 0) && (position.slice == 0)) {
      _nextAddresses(filler, inputBlock, addressBlock);
    }
  }

  bool _isWithXor(_Position position) {
    return !(position.pass == 0 ||
        _parameters.version == Argon2Parameters.ARGON2_VERSION_10);
  }

  int _getPrevOffset(int currentOffset) {
    if (currentOffset % _laneLength == 0) {
      return currentOffset + _laneLength - 1;
    } else {
      return currentOffset - 1;
    }
  }

  static int _getStartingIndex(_Position position) {
    if ((position.pass == 0) && (position.slice == 0)) {
      return 2; 
    } else {
      return 0;
    }
  }

  void _nextAddresses(_FillBlock filler, _Block inputBlock, _Block addressBlock) {
    inputBlock._v[12] = (inputBlock._v[12] + 1) & 0xFFFFFFFF;
    if (inputBlock._v[12] == 0) {
      inputBlock._v[13] = (inputBlock._v[13] + 1) & 0xFFFFFFFF;
    }
    filler.fillBlock(inputBlock, addressBlock);
    filler.fillBlock(addressBlock, addressBlock);
  }

  (int, int) _getPseudoRandom(_FillBlock filler, int index, _Block? addressBlock,
      _Block? inputBlock, int prevOffset, bool dataIndependentAddressing) {
    if (dataIndependentAddressing) {
      var addressIndex = index % ARGON2_ADDRESSES_IN_BLOCK;
      if (addressIndex == 0) {
        _nextAddresses(filler, inputBlock!, addressBlock!);
      }
      return (
        addressBlock!._v[addressIndex * 2],
        addressBlock._v[addressIndex * 2 + 1]
      );
    } else {
      return (
        _memory[prevOffset]._v[0],
        _memory[prevOffset]._v[1]
      );
    }
  }

  int _getRefLane(_Position position, int pseudoRandomJ2) {
    var refLane = (pseudoRandomJ2 % _parameters.lanes);

    if ((position.pass == 0) && (position.slice == 0)) {
      refLane = position.lane;
    }
    return refLane;
  }

  int _getRefColumn(
      _Position position, int index, int pseudoRandomJ1, bool sameLane) {
    int referenceAreaSize;
    int startPosition;

    if (position.pass == 0) {
      startPosition = 0;

      if (sameLane) {
        referenceAreaSize = position.slice * _segmentLength + index - 1;
      } else {
        referenceAreaSize =
            position.slice * _segmentLength + ((index == 0) ? (-1) : 0);
      }
    } else {
      startPosition = ((position.slice + 1) * _segmentLength) % _laneLength;

      if (sameLane) {
        referenceAreaSize = _laneLength - _segmentLength + index - 1;
      } else {
        referenceAreaSize =
            _laneLength - _segmentLength + ((index == 0) ? (-1) : 0);
      }
    }

    var relativePosition = pseudoRandomJ1;
    relativePosition = _FillBlock._mul32High(relativePosition, relativePosition);
    relativePosition = referenceAreaSize -
        1 -
        _FillBlock._mul32High(referenceAreaSize, relativePosition);

    return (startPosition + relativePosition) % _laneLength;
  }

  void _digest(Uint8List tmpBlockBytes, Uint8List out, int outOff, int outLen) {
    var finalBlock = _memory[_laneLength - 1];

    for (var i = 1; i < _parameters.lanes; i++) {
      var lastBlockInLane = i * _laneLength + (_laneLength - 1);
      finalBlock.xorWith(_memory[lastBlockInLane]);
    }

    finalBlock.toBytes(tmpBlockBytes);
    _hash(tmpBlockBytes, out, outOff, outLen);
  }

  void _hash(Uint8List input, Uint8List out, int outOff, int outLen) {
    var outLenBytes = Uint8List(4);
    Pack.intToLittleEndianAtList(outLen, outLenBytes, 0);

    var blake2bLength = 64;

    if (outLen <= blake2bLength) {
      var blake = _Blake2bDigest(digestSize: outLen);
      blake.update(outLenBytes, 0, outLenBytes.length);
      blake.update(input, 0, input.length);
      blake.doFinal(out, outOff);
    } else {
      var digest = _Blake2bDigest(digestSize: blake2bLength);
      var outBuffer = Uint8List(blake2bLength);

      digest.update(outLenBytes, 0, outLenBytes.length);
      digest.update(input, 0, input.length);
      digest.doFinal(outBuffer, 0);

      var halfLen = blake2bLength ~/ 2, outPos = outOff;
      out.setFrom(outPos, outBuffer, 0, halfLen);

      outPos += halfLen;

      var r = ((outLen + 31) ~/ 32) - 2;

      for (var i = 2; i <= r; i++, outPos += halfLen) {
        digest.reset();
        digest.update(outBuffer, 0, outBuffer.length);
        digest.doFinal(outBuffer, 0);
        out.setFrom(outPos, outBuffer, 0, halfLen);
      }

      var lastLength = outLen - 32 * r;
      digest = _Blake2bDigest(digestSize: lastLength);
      digest.update(outBuffer, 0, outBuffer.length);
      digest.doFinal(out, outPos);
    }
  }

  void _initialize(
      Uint8List tmpBlockBytes, Uint8List password, int outputLength) {
    var blake = _Blake2bDigest(digestSize: ARGON2_PREHASH_DIGEST_LENGTH);
    var values = Uint32List.fromList([
      _parameters.lanes,
      outputLength,
      _parameters.memory,
      _parameters.iterations,
      _parameters.version,
      _parameters.type
    ]);

    Pack.intListToLittleEndianAtList(values, tmpBlockBytes, 0);
    blake.update(tmpBlockBytes, 0, values.length * 4);

    _addByteString(tmpBlockBytes, blake, password);
    _addByteString(tmpBlockBytes, blake, _parameters.salt);
    _addByteString(tmpBlockBytes, blake, _parameters.secret);
    _addByteString(tmpBlockBytes, blake, _parameters.additional);

    var initialHashWithZeros = Uint8List(ARGON2_PREHASH_SEED_LENGTH);
    blake.doFinal(initialHashWithZeros, 0);

    _fillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
  }

  static void _addByteString(Uint8List tmpBlockBytes, _Blake2bDigest digest,
      [Uint8List? octets]) {
    if (octets == null) {
      digest.update(_ZERO_BYTES, 0, 4);
      return;
    }

    Pack.intToLittleEndianAtList(octets.length, tmpBlockBytes, 0);
    digest.update(tmpBlockBytes, 0, 4);
    digest.update(octets, 0, octets.length);
  }

  void _fillFirstBlocks(
      Uint8List tmpBlockBytes, Uint8List initialHashWithZeros) {
    var initialHashWithOnes = Uint8List(ARGON2_PREHASH_SEED_LENGTH);
    initialHashWithOnes.setFrom(
        0, initialHashWithZeros, 0, ARGON2_PREHASH_DIGEST_LENGTH);

    initialHashWithOnes[ARGON2_PREHASH_DIGEST_LENGTH] = 1;

    for (var i = 0; i < _parameters.lanes; i++) {
      Pack.intToLittleEndianAtList(
          i, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
      Pack.intToLittleEndianAtList(
          i, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

      _hash(initialHashWithZeros, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
      _memory[i * _laneLength + 0].fromBytes(tmpBlockBytes);

      _hash(initialHashWithOnes, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
      _memory[i * _laneLength + 1].fromBytes(tmpBlockBytes);
    }
  }
}

class _FillBlock {
  final _Block _r = _Block();
  final _Block _z = _Block();
  _Block addressBlock = _Block();
  _Block inputBlock = _Block();

  void _applyBlake() {
    for (var i = 0; i < 8; i++) {
      var i16 = 16 * i;
      _roundFunction(_z, i16, i16 + 1, i16 + 2, i16 + 3, i16 + 4, i16 + 5,
          i16 + 6, i16 + 7, i16 + 8, i16 + 9, i16 + 10, i16 + 11, i16 + 12,
          i16 + 13, i16 + 14, i16 + 15);
    }
    for (var i = 0; i < 8; i++) {
      var i2 = 2 * i;
      _roundFunction(_z, i2, i2 + 1, i2 + 16, i2 + 17, i2 + 32, i2 + 33,
          i2 + 48, i2 + 49, i2 + 64, i2 + 65, i2 + 80, i2 + 81, i2 + 96,
          i2 + 97, i2 + 112, i2 + 113);
    }
  }

  void fillBlock(_Block Y, _Block currentBlock) {
    _z.copyBlock(Y);
    _applyBlake();
    currentBlock.xor(Y, _z);
  }

  void fillBlock2(_Block X, _Block Y, _Block currentBlock) {
    _r.xor(X, Y);
    _z.copyBlock(_r);
    _applyBlake();
    currentBlock.xor(_r, _z);
  }

  void fillBlockWithXor(_Block X, _Block Y, _Block currentBlock) {
    _r.xor(X, Y);
    _z.copyBlock(_r);
    _applyBlake();
    currentBlock.xorWith2(_r, _z);
  }

  static void _roundFunction(_Block block, int v0, int v1, int v2, int v3,
      int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12,
      int v13, int v14, int v15) {
    final v = block._v;
    _F(v, v0, v4, v8, v12);
    _F(v, v1, v5, v9, v13);
    _F(v, v2, v6, v10, v14);
    _F(v, v3, v7, v11, v15);

    _F(v, v0, v5, v10, v15);
    _F(v, v1, v6, v11, v12);
    _F(v, v2, v7, v8, v13);
    _F(v, v3, v4, v9, v14);
  }

  static void _F(Uint32List v, int a, int b, int c, int d) {
    _quarterRound(v, a, b, d, 32);
    _quarterRound(v, c, d, b, 24);
    _quarterRound(v, a, b, d, 16);
    _quarterRound(v, c, d, b, 63);
  }

  static void _quarterRound(
      Uint32List v, int xIdx, int yIdx, int zIdx, int shift) {
    int xLo = xIdx * 2, xHi = xLo + 1;
    int yLo = yIdx * 2, yHi = yLo + 1;
    int zLo = zIdx * 2, zHi = zLo + 1;

    int a32 = v[xLo];
    int b32 = v[yLo];

    int aLo16 = a32 & 0xFFFF, aHi16 = a32 >>> 16;
    int bLo16 = b32 & 0xFFFF, bHi16 = b32 >>> 16;

    int p0 = aLo16 * bLo16;
    int p1 = aHi16 * bLo16;
    int p2 = aLo16 * bHi16;
    int p3 = aHi16 * bHi16;

    int mid = p1 + p2 + (p0 >>> 16);
    int prodLo = ((mid & 0xFFFF) << 16) | (p0 & 0xFFFF);
    int prodHi = p3 + (mid >>> 16);

    int termHi = ((prodHi << 1) | (prodLo >>> 31)) & 0xFFFFFFFF;
    int termLo = (prodLo << 1) & 0xFFFFFFFF;

    int sum1Lo = v[xLo] + v[yLo];
    int sum1Hi = v[xHi] + v[yHi] + (sum1Lo >>> 32);
    sum1Lo &= 0xFFFFFFFF;

    int finalALo = sum1Lo + termLo;
    int finalAHi = sum1Hi + termHi + (finalALo >>> 32);

    v[xLo] = finalALo & 0xFFFFFFFF;
    v[xHi] = finalAHi & 0xFFFFFFFF;

    int cXorALo = (v[zLo] ^ v[xLo]) >>> 0;
    int cXorAHi = (v[zHi] ^ v[xHi]) >>> 0;

    if (shift == 32) {
      v[zLo] = cXorAHi;
      v[zHi] = cXorALo;
    } else if (shift < 32) {
      v[zLo] = ((cXorALo >>> shift) | (cXorAHi << (32 - shift))) & 0xFFFFFFFF;
      v[zHi] = ((cXorAHi >>> shift) | (cXorALo << (32 - shift))) & 0xFFFFFFFF;
    } else {
      int s32 = shift - 32;
      v[zLo] = ((cXorAHi >>> s32) | (cXorALo << (32 - s32))) & 0xFFFFFFFF;
      v[zHi] = ((cXorALo >>> s32) | (cXorAHi << (32 - s32))) & 0xFFFFFFFF;
    }
  }

  // Multiplicação de 32 bits devolvendo os 32 bits mais altos (segura para JS)
  static int _mul32High(int a, int b) {
    int aLo = a & 0xFFFF, aHi = a >>> 16;
    int bLo = b & 0xFFFF, bHi = b >>> 16;
    int p0 = aLo * bLo;
    int p1 = aHi * bLo;
    int p2 = aLo * bHi;
    int p3 = aHi * bHi;
    int mid = p1 + p2 + (p0 >>> 16);
    return p3 + (mid >>> 16);
  }
}

class _Block {
  static const int QWORDS = Argon2BytesGenerator.ARGON2_QWORDS_IN_BLOCK;
  static const int SIZE = QWORDS * 2;

  final Uint32List _v = Uint32List(SIZE);

  _Block();

  void fromBytes(Uint8List input) {
    if (input.length < Argon2BytesGenerator.ARGON2_BLOCK_SIZE) {
      throw ArgumentError.value(
          input.length, 'input.length', 'input shorter than blocksize');
    }
    Pack.littleEndianToLongAtList(input, 0, _v);
  }

  void toBytes(Uint8List output) {
    if (output.length < Argon2BytesGenerator.ARGON2_BLOCK_SIZE) {
      throw ArgumentError.value(
          output.length, 'output.length', 'output shorter than blocksize');
    }
    Pack.longListToLittleEndianAtList(_v, output, 0);
  }

  void copyBlock(_Block other) {
    _v.setAll(0, other._v);
  }

  void xor(_Block b1, _Block b2) {
    for (var i = SIZE - 1; i >= 0; --i) {
      _v[i] = b1._v[i] ^ b2._v[i];
    }
  }

  void xorWith(_Block b1) {
    for (var i = SIZE - 1; i >= 0; --i) {
      _v[i] ^= b1._v[i];
    }
  }

  void xorWith2(_Block b1, _Block b2) {
    for (var i = SIZE - 1; i >= 0; --i) {
      _v[i] ^= b1._v[i] ^ b2._v[i];
    }
  }

  _Block clear() {
    for (var i = SIZE - 1; i >= 0; --i) {
      _v[i] = 0;
    }
    return this;
  }
}

class _Position {
  int pass = 0;
  int lane = 0;
  int slice = 0;

  _Position();
}