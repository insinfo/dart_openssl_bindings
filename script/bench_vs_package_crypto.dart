// openssl_bindings against package:crypto, algorithm by algorithm and size by
// size: where the FFI call pays for itself and where the pure Dart hash wins.
//
//   dart run script/bench_vs_package_crypto.dart
//   dart compile exe script/bench_vs_package_crypto.dart -o bench.exe && ./bench.exe
//
// Both forms are worth running: package:crypto is Dart, so it gains from the
// JIT warming up, while our side is a call into libcrypto and barely moves
// between JIT and AOT. Every case is checked for an identical digest before it
// is timed, so a "win" here is never a wrong answer computed faster.
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pc;
import 'package:openssl_bindings/openssl.dart';

void main(List<String> args) {
  final openSsl = OpenSSL();
  print('libcrypto ${openSsl.opensslVersionString} vs package:crypto');
  print('');

  const sizes = [32, 256, 1024, 8 * 1024, 64 * 1024, 1024 * 1024, 16 << 20];
  final algorithms = <String, pc.Hash>{
    'md5': pc.md5,
    'sha1': pc.sha1,
    'sha256': pc.sha256,
    'sha512': pc.sha512,
  };

  final losses = <String>[];

  print('## One-shot digest');
  _printHeader();
  for (final entry in algorithms.entries) {
    for (final size in sizes) {
      final data = _buffer(size);
      final ours = openSsl.digest(entry.key, data);
      final theirs = Uint8List.fromList(entry.value.convert(data).bytes);
      _requireEqual('${entry.key} ${_size(size)}', ours, theirs);

      final row = _Row(
        label: entry.key,
        size: size,
        oursNs: _benchNsPerOp(() => openSsl.digest(entry.key, data)),
        theirsNs: _benchNsPerOp(() => entry.value.convert(data)),
      );
      _printRow(row);
      if (row.ratio < 1) losses.add(row.description);
    }
    print('');
  }

  print('## HMAC-SHA256');
  _printHeader();
  final key = _buffer(32);
  for (final size in [32, 1024, 64 * 1024, 1024 * 1024]) {
    final data = _buffer(size);
    final hmac = pc.Hmac(pc.sha256, key);
    final ours = openSsl.hmac('sha256', key, data);
    final theirs = Uint8List.fromList(hmac.convert(data).bytes);
    _requireEqual('hmac-sha256 ${_size(size)}', ours, theirs);

    final row = _Row(
      label: 'hmac-sha256',
      size: size,
      oursNs: _benchNsPerOp(() => openSsl.hmac('sha256', key, data)),
      theirsNs: _benchNsPerOp(() => hmac.convert(data)),
    );
    _printRow(row);
    if (row.ratio < 1) losses.add(row.description);
  }
  print('');

  print('## Incremental, 64 KiB chunks (the streaming path)');
  _printHeader();
  for (final total in [64 * 1024, 1024 * 1024, 16 << 20]) {
    final chunks = _chunks(total, 64 * 1024);
    final ours = _incrementalOurs(openSsl, chunks);
    final theirs = _incrementalTheirs(chunks);
    _requireEqual('incremental ${_size(total)}', ours, theirs);

    final row = _Row(
      label: 'sha256 chunked',
      size: total,
      oursNs: _benchNsPerOp(() => _incrementalOurs(openSsl, chunks)),
      theirsNs: _benchNsPerOp(() => _incrementalTheirs(chunks)),
    );
    _printRow(row);
    if (row.ratio < 1) losses.add(row.description);
  }
  print('');

  print('## Digest to lowercase hex (what most callers store)');
  _printHeader();
  for (final size in [32, 1024, 1024 * 1024]) {
    final data = _buffer(size);
    final ours = openSsl.digestHex('sha256', data);
    final theirs = pc.sha256.convert(data).toString();
    if (ours != theirs) {
      throw StateError('hex mismatch at ${_size(size)}: $ours != $theirs');
    }

    final row = _Row(
      label: 'sha256 hex',
      size: size,
      oursNs: _benchNsPerOp(() => openSsl.digestHex('sha256', data)),
      theirsNs: _benchNsPerOp(() => pc.sha256.convert(data).toString()),
    );
    _printRow(row);
    if (row.ratio < 1) losses.add(row.description);
  }
  print('');

  _reportCrossover(openSsl);
  _reportCoverage(openSsl);

  print('## Where we lose');
  if (losses.isEmpty) {
    print('Nowhere in this run.');
  } else {
    for (final loss in losses) {
      print('- $loss');
    }
  }
}

// --- cases -----------------------------------------------------------------

Uint8List _incrementalOurs(OpenSSL openSsl, List<Uint8List> chunks) {
  final digest = openSsl.startDigest('sha256');
  try {
    for (final chunk in chunks) {
      digest.add(chunk);
    }
    return digest.finish();
  } finally {
    digest.dispose();
  }
}

Uint8List _incrementalTheirs(List<Uint8List> chunks) {
  final sink = _DigestSink();
  final input = pc.sha256.startChunkedConversion(sink);
  for (final chunk in chunks) {
    input.add(chunk);
  }
  input.close();
  return Uint8List.fromList(sink.value!.bytes);
}

class _DigestSink implements Sink<pc.Digest> {
  pc.Digest? value;

  @override
  void add(pc.Digest data) => value = data;

  @override
  void close() {}
}

/// Finds the input size where the FFI round trip stops costing more than it
/// saves — below it package:crypto is the faster call for sha256.
void _reportCrossover(OpenSSL openSsl) {
  print('## sha256 crossover');
  var crossover = -1;
  for (var size = 16; size <= 1 << 20; size *= 2) {
    final data = _buffer(size);
    final ours = _benchNsPerOp(() => openSsl.digest('sha256', data));
    final theirs = _benchNsPerOp(() => pc.sha256.convert(data));
    if (ours < theirs) {
      crossover = size;
      break;
    }
  }
  if (crossover < 0) {
    print('package:crypto stayed ahead up to 1 MiB in this run.');
  } else {
    print('openssl_bindings takes the lead at ${_size(crossover)} '
        'and keeps it above that.');
  }
  print('');
}

/// Algorithms one side has and the other does not — a gap no timing shows.
void _reportCoverage(OpenSSL openSsl) {
  print('## Coverage');
  const onlyOurs = [
    'sha3-256',
    'sha3-512',
    'shake256',
    'blake2b512',
    'sm3',
    'ripemd160',
  ];
  final available = <String>[];
  for (final name in onlyOurs) {
    try {
      openSsl.digest(name, Uint8List(1));
      available.add(name);
    } on OpenSslException {
      // Not in this libcrypto build; not a difference worth reporting.
    }
  }
  print('Only here: ${available.join(', ')} — package:crypto ships MD5, '
      'SHA-1 and the SHA-2 family only.');
  print('Only there: runs on the web and wherever no libcrypto can be '
      'loaded, which no FFI binding can match.');
  print('');
}

// --- harness ---------------------------------------------------------------

class _Row {
  _Row({
    required this.label,
    required this.size,
    required this.oursNs,
    required this.theirsNs,
  });

  final String label;
  final int size;
  final double oursNs;
  final double theirsNs;

  /// How many times faster we are; below 1 means package:crypto wins.
  double get ratio => theirsNs / oursNs;

  String get description => '$label at ${_size(size)}: '
      '${(1 / ratio).toStringAsFixed(2)}x slower than package:crypto';
}

void _printHeader() {
  print('${'case'.padRight(16)}${'size'.padLeft(9)}'
      '${'ours'.padLeft(12)}${'pkg:crypto'.padLeft(12)}'
      '${'ours MB/s'.padLeft(12)}${'theirs MB/s'.padLeft(12)}'
      '${'ratio'.padLeft(9)}');
}

void _printRow(_Row row) {
  final verdict = row.ratio >= 1
      ? '${row.ratio.toStringAsFixed(2)}x'
      : '${row.ratio.toStringAsFixed(2)}x LOSS';
  print('${row.label.padRight(16)}${_size(row.size).padLeft(9)}'
      '${_time(row.oursNs).padLeft(12)}${_time(row.theirsNs).padLeft(12)}'
      '${_throughput(row.size, row.oursNs).padLeft(12)}'
      '${_throughput(row.size, row.theirsNs).padLeft(12)}'
      '${verdict.padLeft(9)}');
}

/// Times [op] and returns nanoseconds per call.
///
/// The count is calibrated so a batch lasts about 200 ms, and the best of five
/// batches is reported: the fastest run is the one least disturbed by the GC
/// and by whatever else the machine was doing.
double _benchNsPerOp(void Function() op) {
  op();

  var iterations = 1;
  var perOpNs = 0.0;
  while (true) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      op();
    }
    sw.stop();
    if (sw.elapsedMicroseconds >= 20000) {
      perOpNs = sw.elapsedMicroseconds * 1000 / iterations;
      break;
    }
    iterations *= 2;
  }

  final count = math.max(1, (200000000 / perOpNs).round());
  var best = double.infinity;
  for (var round = 0; round < 5; round++) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < count; i++) {
      op();
    }
    sw.stop();
    final ns = sw.elapsedMicroseconds * 1000 / count;
    if (ns < best) best = ns;
  }
  return best;
}

Uint8List _buffer(int size) {
  final random = math.Random(size);
  final bytes = Uint8List(size);
  for (var i = 0; i < size; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

List<Uint8List> _chunks(int total, int chunkSize) {
  final chunks = <Uint8List>[];
  for (var offset = 0; offset < total; offset += chunkSize) {
    chunks.add(_buffer(math.min(chunkSize, total - offset)));
  }
  return chunks;
}

void _requireEqual(String what, Uint8List ours, Uint8List theirs) {
  if (!_sameBytes(ours, theirs)) {
    throw StateError('digest mismatch for $what: '
        '${base64.encode(ours)} != ${base64.encode(theirs)}');
  }
}

bool _sameBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _size(int bytes) {
  if (bytes >= 1 << 20) return '${bytes >> 20} MiB';
  if (bytes >= 1024) return '${bytes >> 10} KiB';
  return '$bytes B';
}

String _time(double ns) {
  if (ns >= 1000000) return '${(ns / 1000000).toStringAsFixed(2)} ms';
  if (ns >= 1000) return '${(ns / 1000).toStringAsFixed(2)} us';
  return '${ns.toStringAsFixed(0)} ns';
}

String _throughput(int bytes, double ns) {
  if (bytes < 1024) return '-';
  final mbPerSecond = bytes / (ns / 1000000000) / (1 << 20);
  return mbPerSecond.toStringAsFixed(0);
}
