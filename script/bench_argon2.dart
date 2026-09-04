// Argon2 timings: native (OpenSSL 3.2+) against the pure Dart fallback.
//
//   dart run script/bench_argon2.dart
//   dart compile exe script/bench_argon2.dart -o bench_argon2.exe && ./bench_argon2.exe
//
// The second form is what a deployed backend runs, and the JIT and AOT numbers
// differ, so measure both. Point OPENSSL_LIBCRYPTO_PATH / OPENSSL_LIBSSL_PATH
// at another build to compare libcrypto versions.
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

void main(List<String> args) {
  final openSsl = OpenSSL();
  print('libcrypto ${openSsl.opensslVersionString}, '
      'native Argon2: ${openSsl.hasNativeArgon2}');

  const profiles = [
    Argon2Options(memoryKib: 19456, iterations: 2, lanes: 1),
    Argon2Options(memoryKib: 32768, iterations: 3, lanes: 1),
    Argon2Options(memoryKib: 65536, iterations: 3, lanes: 1),
    Argon2Options(memoryKib: 65536, iterations: 3, lanes: 4),
  ];

  for (final backend in Argon2Backend.values) {
    if (backend == Argon2Backend.native && !openSsl.hasNativeArgon2) continue;
    for (final options in profiles) {
      // OpenSSL only accepts lanes > 1 with a thread pool configured.
      if (backend == Argon2Backend.native && options.lanes > 1) continue;
      _bench(openSsl, options, backend);
    }
  }
}

void _bench(OpenSSL openSsl, Argon2Options options, Argon2Backend backend) {
  final password = Uint8List.fromList('correct horse battery staple'.codeUnits);
  final salt = Uint8List.fromList(List.generate(16, (i) => i));

  openSsl.argon2Derive(password, salt, options: options, backend: backend);

  const runs = 5;
  final times = <int>[];
  for (var i = 0; i < runs; i++) {
    final stopwatch = Stopwatch()..start();
    openSsl.argon2Derive(password, salt, options: options, backend: backend);
    times.add(stopwatch.elapsedMilliseconds);
  }
  final average = times.reduce((a, b) => a + b) / runs;

  print(
      '${backend.name.padRight(6)} m=${options.memoryKib.toString().padLeft(5)} '
      't=${options.iterations} p=${options.lanes}: '
      '${average.toStringAsFixed(1).padLeft(7)} ms  (${times.join(' ')})');
}
