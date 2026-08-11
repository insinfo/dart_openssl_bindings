// Multiple isolates driving OpenSSL at the same time, in one process.
//
// This mirrors the shape of a production Dart backend rather than a microbench:
// several *long-lived* worker isolates stay up for the life of the process (the
// HTTP server isolates a runner spawns with `-j N`, plus notification, e-mail
// and background-job workers), while *short-lived* job isolates are spawned and
// torn down continuously for one-off CPU work — PDF signing, for instance. All
// of them load their own OpenSSL and hammer it concurrently.
//
// What these tests are actually looking for:
//
// - **Crashes.** A native double free or a pointer used from the wrong isolate
//   takes down the whole process, not one test. Uncaught isolate errors are
//   collected and asserted on.
// - **Wrong answers.** Every digest, MAC and signature computed in a worker is
//   compared against the same computation in the main isolate. Shared native
//   state between isolates would show up here as a corrupted result long before
//   it showed up as a crash.
// - **Leaks.** Native allocations are invisible to the Dart GC, so a missing
//   free shows up only as RSS growth. The last test watches RSS across rounds.
//
// Tunable from the environment, to run heavier locally than on CI:
// `ISOLATE_STRESS_WORKERS`, `ISOLATE_STRESS_JOBS`, `ISOLATE_STRESS_ROUNDS`,
// `ISOLATE_STRESS_MAX_MB`.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

int _envInt(String name, int fallback) =>
    int.tryParse(Platform.environment[name] ?? '') ?? fallback;

double _envDouble(String name, double fallback) =>
    double.tryParse(Platform.environment[name] ?? '') ?? fallback;

String _formatBytes(int bytes) =>
    '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';

/// How much the *floor* of [samples] rose between its first and second half,
/// in MB.
///
/// Comparing the first reading to the last would be measuring the Dart heap's
/// sawtooth, not a leak: across isolates doing real work, RSS swings by tens of
/// megabytes between collections, so first-vs-last lands wherever the GC
/// happened to be and the assertion becomes a coin flip. The minimum of each
/// half is the part that a collection cannot give back — native memory that was
/// allocated and never freed pushes it up, and nothing else does.
double _floorGrowthMb(List<int> samples) {
  final half = samples.length ~/ 2;
  final earlyFloor = samples.take(half).reduce(math.min);
  final lateFloor = samples.skip(half).reduce(math.min);
  return (lateFloor - earlyFloor) / (1024 * 1024);
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List _payload(int seed, int length) =>
    Uint8List.fromList(List<int>.generate(length, (i) => (i * 31 + seed) % 256));

/// Digests [data] in a throwaway isolate — the one-off `Isolate.run` job shape.
///
/// This helper lives at the top level on purpose, and that detail matters more
/// than it looks. A closure sent to another isolate carries its entire captured
/// context, including the *parent* scopes it never reads. Written inline inside
/// a test, the closure below would drag in the enclosing function's variables —
/// among them the main isolate's [OpenSSL], whose `DynamicLibrary` is not
/// sendable — and the spawn would die with:
///
/// ```text
/// Invalid argument(s): Illegal argument in isolate message:
///   (object is a DynamicLibrary)
/// ```
///
/// Hoisting the spawn into a top-level function whose scope holds only sendable
/// data is the fix. This is the easiest way to get isolates and this package
/// wrong, so it is pinned by a test below rather than left to a comment.
Future<String> _digestInFreshIsolate(Uint8List data) => Isolate.run(() {
      // A fresh instance per short-lived isolate: the native handles held by an
      // instance belong to the isolate that created it.
      final isolateSsl = OpenSSL();
      return isolateSsl.digestHex('sha256', data);
    });

void main() {
  final workerCount = _envInt('ISOLATE_STRESS_WORKERS', 4);
  final jobsPerWorker = _envInt('ISOLATE_STRESS_JOBS', 12);

  late OpenSSL openSsl;
  late Directory tempDir;
  late File sharedFile;
  late Uint8List sharedFileBytes;

  setUpAll(() {
    openSsl = OpenSSL();
    tempDir = Directory.systemTemp.createTempSync('openssl_isolate_stress');
    // Big enough that `openRead` hands out many chunks, so the streaming digest
    // in each isolate really does loop.
    sharedFileBytes = _payload(7, 2 * 1024 * 1024);
    sharedFile = File('${tempDir.path}/shared.bin')
      ..writeAsBytesSync(sharedFileBytes);
  });

  tearDownAll(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  group('Long-lived worker isolates', () {
    test(
      'serve a mixed workload concurrently and agree with the main isolate',
      () async {
        final workers = await _WorkerPool.spawn(workerCount);
        try {
          final expectedFileDigest = openSsl.digestHex(
            'sha256',
            sharedFileBytes,
          );

          // Every worker gets every job type, so no isolate sits on a single
          // code path while the others exercise the interesting ones.
          final pending = <Future<void>>[];
          for (var w = 0; w < workerCount; w++) {
            for (var j = 0; j < jobsPerWorker; j++) {
              final data = _payload(w * 1000 + j, 4096);
              final worker = workers[w];

              switch (j % 5) {
                case 0:
                  final expected = openSsl.digestHex('sha256', data);
                  pending.add(
                    worker.request({'type': 'digest', 'data': data}).then(
                      (value) => expect(
                        value,
                        equals(expected),
                        reason: 'digest from worker ${worker.id}',
                      ),
                    ),
                  );
                case 1:
                  final key = _payload(j, 32);
                  final expected = openSsl.hmac('sha256', key, data);
                  pending.add(
                    worker.request({
                      'type': 'hmac',
                      'key': key,
                      'data': data,
                    }).then(
                      (value) => expect(
                        _bytesEqual(value as Uint8List, expected),
                        isTrue,
                        reason: 'hmac from worker ${worker.id}',
                      ),
                    ),
                  );
                case 2:
                  pending.add(
                    worker.request({'type': 'aes', 'data': data}).then(
                      (value) => expect(
                        value,
                        isTrue,
                        reason: 'aes round trip in worker ${worker.id}',
                      ),
                    ),
                  );
                case 3:
                  pending.add(
                    worker.request({
                      'type': 'digestFile',
                      'path': sharedFile.path,
                    }).then((value) {
                      final result = (value as List).cast<Object>();
                      expect(
                        result[0],
                        equals(expectedFileDigest),
                        reason: 'streamed digest from worker ${worker.id}',
                      );
                      expect(result[1], equals(sharedFileBytes.length));
                    }),
                  );
                case 4:
                  pending.add(
                    worker.request({'type': 'signVerify', 'data': data}).then(
                      (value) => expect(
                        value,
                        isTrue,
                        reason: 'RSA sign/verify in worker ${worker.id}',
                      ),
                    ),
                  );
              }
            }
          }

          await Future.wait(pending);
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );

    test(
      'build and parse certificates in parallel without mixing state up',
      () async {
        final workers = await _WorkerPool.spawn(workerCount);
        try {
          final results = await Future.wait([
            for (var w = 0; w < workerCount; w++)
              workers[w].request({'type': 'certificate'}),
          ]);

          // Each isolate signs its own certificate with its own key. A subject
          // showing up under the wrong worker id would mean native state
          // leaking across isolates.
          for (var w = 0; w < workerCount; w++) {
            final cert = (results[w] as List).cast<Object>();
            expect(cert[0] as String, contains('Worker $w'));
            expect(cert[1] as String, contains('Worker $w'));
            expect(cert[2] as String, startsWith('-----BEGIN CERTIFICATE-----'));
          }
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );
  });

  group('Mixed topology', () {
    test(
      'short-lived job isolates churn while the long-lived workers stay busy',
      () async {
        // The production shape: persistent workers serving a steady load while
        // one-off `Isolate.run` jobs — the PDF signing pattern — are spawned and
        // discarded underneath them. Each short-lived isolate pays for its own
        // load of libcrypto, which is exactly what makes this worth measuring
        // before moving small hashes off a pure-Dart implementation.
        final workers = await _WorkerPool.spawn(workerCount);
        try {
          final steadyLoad = <Future<void>>[];
          for (var w = 0; w < workerCount; w++) {
            for (var j = 0; j < jobsPerWorker; j++) {
              final data = _payload(w + j, 8192);
              final expected = openSsl.digestHex('sha256', data);
              steadyLoad.add(
                workers[w]
                    .request({'type': 'digest', 'data': data})
                    .then((value) => expect(value, equals(expected))),
              );
            }
          }

          final churn = <Future<void>>[];
          for (var i = 0; i < workerCount * 3; i++) {
            final data = _payload(i * 17, 8192);
            final expected = openSsl.digestHex('sha256', data);
            churn.add(
              _digestInFreshIsolate(
                data,
              ).then((value) => expect(value, equals(expected))),
            );
          }

          await Future.wait([...steadyLoad, ...churn]);
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );

    test(
      'the main isolate keeps working while the workers do',
      () async {
        // The runner process does OpenSSL work on the main isolate too, so the
        // main instance has to stay usable while the workers are loaded.
        final workers = await _WorkerPool.spawn(workerCount);
        try {
          final workerLoad = [
            for (var w = 0; w < workerCount; w++)
              for (var j = 0; j < jobsPerWorker; j++)
                workers[w].request({
                  'type': 'digestFile',
                  'path': sharedFile.path,
                }),
          ];

          final expected = openSsl.digestHex('sha256', sharedFileBytes);
          for (var i = 0; i < jobsPerWorker; i++) {
            final digest = openSsl.startDigest('sha256');
            try {
              await digest.addStream(sharedFile.openRead());
              expect(digest.finishHex(), equals(expected));
              expect(digest.length, equals(sharedFileBytes.length));
            } finally {
              digest.dispose();
            }
          }

          for (final result in await Future.wait(workerLoad)) {
            expect((result as List)[0], equals(expected));
          }
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );
  });

  group('Isolate boundary', () {
    test('an OpenSSL instance cannot be sent to another isolate', () async {
      // Pins the rule every other test here is built around. The instance holds
      // a `DynamicLibrary`, which is not sendable, so it — and anything holding
      // a handle from it (`EvpPkey`, `X509Certificate`, `EvpDigest`) — belongs
      // to the isolate that created it. Each isolate must build its own.
      //
      // The trap is that this is easy to do by accident: a closure passed to
      // `Isolate.run` carries its whole captured context, so merely writing it
      // in a scope where an `OpenSSL` variable exists is enough to drag the
      // instance along, even if the closure never mentions it.
      final instance = openSsl;
      Object? failure;
      try {
        await Isolate.run(() => instance.opensslVersionString);
      } catch (error) {
        failure = error;
      }

      expect(failure, isA<ArgumentError>());
      expect('$failure', contains('DynamicLibrary'));
    });

    test('a fresh instance per isolate agrees with the main one', () async {
      final data = _payload(11, 4096);
      expect(
        await _digestInFreshIsolate(data),
        equals(openSsl.digestHex('sha256', data)),
      );
    });
  });

  group('Failure isolation', () {
    test(
      'an OpenSSL error in one isolate leaves the others working',
      () async {
        final workers = await _WorkerPool.spawn(workerCount);
        try {
          final failure = await workers[0].requestRaw({'type': 'boom'});
          expect(failure['ok'], isFalse);
          expect(failure['error'] as String, contains('not-a-digest'));

          // The isolate that raised must still answer, and so must its peers:
          // a failed operation should not poison the instance or the process.
          final data = _payload(99, 4096);
          final expected = openSsl.digestHex('sha256', data);
          for (var w = 0; w < workerCount; w++) {
            expect(
              await workers[w].request({'type': 'digest', 'data': data}),
              equals(expected),
              reason: 'worker $w after the failure in worker 0',
            );
          }
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );
  });

  group('Native memory across isolates', () {
    test(
      'repeated rounds do not grow the process resident set',
      () async {
        // RSS is measured for the whole process, so it covers what every
        // isolate allocated natively. A digest context or key leaked per job
        // would climb steadily here; Dart's GC would never report it.
        final rounds = _envInt('ISOLATE_STRESS_ROUNDS', 5);
        const warmupRounds = 1;
        final maxAllowedDeltaMb = _envDouble('ISOLATE_STRESS_MAX_MB', 100.0);

        final workers = await _WorkerPool.spawn(workerCount);
        try {
          print('RSS before: ${_formatBytes(ProcessInfo.currentRss)}');
          final measured = <int>[];

          for (var round = 1; round <= rounds; round++) {
            final batch = <Future<Object?>>[];
            for (var w = 0; w < workerCount; w++) {
              for (var j = 0; j < jobsPerWorker; j++) {
                final data = _payload(round * 100 + j, 16 * 1024);
                batch.add(
                  workers[w].request(
                    j.isEven
                        ? {'type': 'digest', 'data': data}
                        : {'type': 'digestFile', 'path': sharedFile.path},
                  ),
                );
              }
            }
            await Future.wait(batch);

            // Give each isolate's event loop a moment to settle before reading
            // RSS, otherwise the measurement catches transient buffers.
            await Future<void>.delayed(const Duration(milliseconds: 50));

            final rssRound = ProcessInfo.currentRss;
            if (round > warmupRounds) measured.add(rssRound);
            print('RSS after round $round: ${_formatBytes(rssRound)}');
          }

          final growthMb = _floorGrowthMb(measured);
          print('RSS floor growth: ${growthMb.toStringAsFixed(2)} MB');
          print('RSS limit: ${maxAllowedDeltaMb.toStringAsFixed(2)} MB');

          expect(growthMb, lessThan(maxAllowedDeltaMb));
          workers.expectNoUncaughtErrors();
        } finally {
          await workers.shutdown();
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );

    test(
      'spawning and discarding isolates repeatedly does not grow the process',
      () async {
        // The `Isolate.run` pattern: every round loads OpenSSL in a fresh
        // isolate and throws it away. If tearing an isolate down left native
        // state behind, this is where it would accumulate.
        final rounds = _envInt('ISOLATE_STRESS_ROUNDS', 5);
        const warmupRounds = 1;
        final maxAllowedDeltaMb = _envDouble('ISOLATE_STRESS_MAX_MB', 100.0);

        final measured = <int>[];
        final data = _payload(3, 32 * 1024);
        final expected = openSsl.digestHex('sha256', data);

        for (var round = 1; round <= rounds; round++) {
          final batch = <Future<String>>[];
          for (var i = 0; i < workerCount; i++) {
            batch.add(_digestInFreshIsolate(data));
          }
          for (final value in await Future.wait(batch)) {
            expect(value, equals(expected));
          }

          await Future<void>.delayed(const Duration(milliseconds: 50));

          final rssRound = ProcessInfo.currentRss;
          if (round > warmupRounds) measured.add(rssRound);
          print('RSS after spawn round $round: ${_formatBytes(rssRound)}');
        }

        final growthMb = _floorGrowthMb(measured);
        print('RSS floor growth across spawn rounds: '
            '${growthMb.toStringAsFixed(2)} MB');
        expect(growthMb, lessThan(maxAllowedDeltaMb));
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });
}

/// A long-lived worker isolate holding one [OpenSSL] instance for its lifetime.
class _Worker {
  _Worker._(this.id, this._isolate, this._outbox, this._exit, this.errors);

  /// Spawns the isolate and waits for it to hand back its inbox.
  static Future<_Worker> spawn(int id) async {
    final handshake = ReceivePort();
    final errorPort = ReceivePort();
    final exitPort = ReceivePort();
    final errors = <String>[];
    errorPort.listen((error) => errors.add('$error'));

    final isolate = await Isolate.spawn(
      _workerMain,
      [handshake.sendPort, id],
      onError: errorPort.sendPort,
      onExit: exitPort.sendPort,
      debugName: 'openssl-worker-$id',
    );

    final outbox = await handshake.first as SendPort;
    handshake.close();
    return _Worker._(id, isolate, outbox, exitPort, errors);
  }

  final int id;
  final Isolate _isolate;
  final SendPort _outbox;
  final ReceivePort _exit;

  /// Uncaught errors reported by this isolate. Anything here means the isolate
  /// died on a path the worker loop did not catch.
  final List<String> errors;

  /// Sends [job] and returns the raw reply envelope, failure included.
  Future<Map<String, Object?>> requestRaw(Map<String, Object?> job) async {
    final reply = ReceivePort();
    _outbox.send({...job, 'reply': reply.sendPort});
    final envelope = await reply.first as Map;
    reply.close();
    return envelope.cast<String, Object?>();
  }

  /// Sends [job] and returns its value, turning a worker-side failure into a
  /// test failure here rather than a silent wrong answer.
  Future<Object?> request(Map<String, Object?> job) async {
    final envelope = await requestRaw(job);
    if (envelope['ok'] != true) {
      fail('worker $id failed job ${job['type']}: ${envelope['error']}');
    }
    return envelope['value'];
  }

  Future<void> shutdown() async {
    _outbox.send(_shutdownMessage);
    await _exit.first.timeout(
      const Duration(seconds: 30),
      onTimeout: () {
        _isolate.kill(priority: Isolate.immediate);
        return null;
      },
    );
    _exit.close();
  }
}

/// The set of workers, with the assertions that apply to all of them.
class _WorkerPool {
  _WorkerPool._(this._workers);

  static Future<_WorkerPool> spawn(int count) async => _WorkerPool._(
        await Future.wait([for (var i = 0; i < count; i++) _Worker.spawn(i)]),
      );

  final List<_Worker> _workers;

  _Worker operator [](int index) => _workers[index];

  void expectNoUncaughtErrors() {
    for (final worker in _workers) {
      expect(
        worker.errors,
        isEmpty,
        reason: 'worker ${worker.id} reported uncaught errors',
      );
    }
  }

  Future<void> shutdown() async =>
      Future.wait(_workers.map((worker) => worker.shutdown())).then((_) {});
}

const String _shutdownMessage = 'shutdown';

/// Entry point of a worker isolate.
///
/// Jobs are handled without awaiting the previous one, so several can overlap
/// inside the isolate — a streamed file digest stays parked on I/O while the
/// next job starts. That is what a server isolate actually does, and it is what
/// would expose state shared between concurrent operations on one instance.
Future<void> _workerMain(List<Object> bootstrap) async {
  final handshake = bootstrap[0] as SendPort;
  final workerId = bootstrap[1] as int;

  // One instance per isolate. Native pointers are not sendable and are only
  // valid in the isolate that created them, so this is the boundary: an
  // `OpenSSL` — and everything holding a handle from it — belongs to its
  // isolate and cannot be handed to another.
  final openSsl = OpenSSL();
  final inbox = ReceivePort();
  handshake.send(inbox.sendPort);

  inbox.listen((message) async {
    if (message == _shutdownMessage) {
      inbox.close();
      return;
    }
    final job = (message as Map).cast<String, Object?>();
    final reply = job['reply'] as SendPort;
    try {
      reply.send(<String, Object?>{
        'ok': true,
        'value': await _runJob(openSsl, workerId, job),
      });
    } catch (error) {
      reply.send(<String, Object?>{'ok': false, 'error': '$error'});
    }
  });
}

Future<Object?> _runJob(
  OpenSSL openSsl,
  int workerId,
  Map<String, Object?> job,
) async {
  switch (job['type'] as String) {
    case 'digest':
      return openSsl.digestHex('sha256', job['data'] as Uint8List);

    case 'digestFile':
      final digest = openSsl.startDigest('sha256');
      try {
        await digest.addStream(File(job['path'] as String).openRead());
        return <Object>[digest.finishHex(), digest.length];
      } finally {
        digest.dispose();
      }

    case 'hmac':
      return openSsl.hmac(
        'sha256',
        job['key'] as Uint8List,
        job['data'] as Uint8List,
      );

    case 'aes':
      final data = job['data'] as Uint8List;
      final key = Uint8List(32)..fillRange(0, 32, workerId + 1);
      final iv = Uint8List(16)..fillRange(0, 16, workerId + 1);
      final cipher = openSsl.aes256CbcEncrypt(data: data, key: key, iv: iv);
      final plain =
          openSsl.aes256CbcDecrypt(ciphertext: cipher, key: key, iv: iv);
      return _bytesEqual(plain, data);

    case 'signVerify':
      final data = job['data'] as Uint8List;
      final key = openSsl.generateRsa(2048);
      try {
        final signature = openSsl.sign(key, data);
        final tampered = Uint8List.fromList(data)..[0] ^= 0xFF;
        // Both directions: a signature that verifies is only meaningful if the
        // same key rejects data it did not sign.
        return openSsl.verify(key, data, signature) &&
            !openSsl.verify(key, tampered, signature);
      } finally {
        key.dispose();
      }

    case 'certificate':
      final key = openSsl.generateRsa(2048);
      try {
        final cert = (X509CertificateBuilder(openSsl)
              ..setSubject(commonName: 'Worker $workerId')
              ..setIssuerAsSubject()
              ..setPublicKey(key)
              ..setValidity(notAfterOffset: 3600))
            .sign(key);
        try {
          return <Object>[cert.subject, cert.issuer, cert.toPem()];
        } finally {
          cert.dispose();
        }
      } finally {
        key.dispose();
      }

    case 'boom':
      // A deliberate OpenSSL-level failure, to prove it stays contained.
      return openSsl.digest('not-a-digest', Uint8List.fromList(utf8.encode('x')));

    default:
      throw ArgumentError('unknown job type: ${job['type']}');
  }
}
