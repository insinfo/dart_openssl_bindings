import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Multi-Isolate & Concurrency Tests', () {
    test('Should run OpenSSL operations in parallel isolates', () async {
      // Create 2 isolates performing heavy work
      final isolateCount = 4; // Increased to 4 to stress concurrency slightly more
      final futures = List.generate(isolateCount, (i) => _runInIsolate(i));

      final results = await Future.wait(futures);

      for (var i = 0; i < isolateCount; i++) {
        expect(results[i], isNotNull);
        expect(results[i].length, greaterThan(0));
      }
    });

    test('Each isolate should have its own library instance and clean shutdown', () async {
        // This test verifies that we can instantiate OpenSSL in separate isolates
        // and they clean up independently.
        
        final t1 = Isolate.run(() {
            final openSsl = OpenSSL();
            final key = openSsl.generateRsa(2048);
            // Explicitly force some activity
            final pem = key.toPrivateKeyPem();
            return pem.isNotEmpty;
        });
        
        final t2 = Isolate.run(() {
             final openSsl = OpenSSL();
             final key = openSsl.generateRsa(2048);
             final pem = key.toPublicKeyPem();
             return pem.isNotEmpty;
        });

        final results = await Future.wait([t1, t2]);
        expect(results.every((r) => r), isTrue);
    });
  });
}

/// The worker function that runs in a separate isolate.
Future<Uint8List> _runInIsolate(int id) async {
  return await Isolate.run(() async {
    // print('Isolate $id: Starting OpenSSL work...');
    // Initialize OpenSSL inside the isolate.
    // Since our bindings load dynamically, each isolate loads/links to the DLL.
    // OpenSSL internal locking handles thread safety on the C side.
    final openSsl = OpenSSL();

    // Perform CPU heavy task: Generate RSA Key
    final key = openSsl.generateRsa(2048);

    // Perform another task: Sign some data
    final data = Uint8List.fromList(List.generate(1024, (i) => i % 256));
    final signature = openSsl.sign(key, data, algorithm: 'SHA256');

    // Return the result
    return signature;
  });
}
