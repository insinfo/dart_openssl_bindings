import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/ssl/secure_socket_openssl_async.dart';

import 'package:test/test.dart';

void main() {
  group('TLS Integration Tests', () {
    late OpenSSL openSsl;
    late Directory tempDir;
    late String certPath;
    late String keyPath;

    setUpAll(() async {
      openSsl = OpenSSL();
      tempDir = await Directory.systemTemp.createTemp('openssl_tests_');
      certPath = '${tempDir.path}/server.crt';
      keyPath = '${tempDir.path}/server.key';

      // 1. Generate Key
      final pkey = openSsl.generateRsa(2048);

      // 2. Generate Self-Signed Cert
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(
        commonName: 'localhost',
        organization: 'Test Org',
        country: 'US',
      );
      builder.setIssuerAsSubject();
      builder.setValidity(notAfterOffset: 3600); // 1 hour
      builder.setPublicKey(pkey);

      final cert = builder.sign(pkey);

      // 3. Save to disk
      await File(keyPath).writeAsString(pkey.toPrivateKeyPem());
      await File(certPath).writeAsString(cert.toPem());
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    test('Should establish TLS connection and exchange data', () async {
      final completer = Completer<void>();
      final serverSocket = await ServerSocket.bind('127.0.0.1', 0);
      final port = serverSocket.port;

      // Server Logic
      serverSocket.listen((clientSocket) async {
        try {
          final secureSocket = SecureSocketOpenSslAsync.serverFromSocket(
            clientSocket,
            certFile: certPath,
            keyFile: keyPath,
            eagerHandshake: true,
          );

          await secureSocket.ensureHandshakeCompleted();

          final data = await secureSocket.recv(1024);
          final message = String.fromCharCodes(data);
          expect(message, equals('Ping'));

          await secureSocket.send(Uint8List.fromList('Pong'.codeUnits));
          await secureSocket.close();
        } catch (e, st) {
          if (!completer.isCompleted) {
            completer.completeError(e, st);
          }
        }
      });

      // Client Logic
      try {
        // Wait a bit for server to be ready (though simple socket bind is usually instant)
        await Future.delayed(Duration(milliseconds: 100));

        // Note: Using standard dart:io Socket for initial connection to pass to our wrapper
        // Or using our static helper.
        // Also: Our client implementation uses OpenSSL, so it validates certificates by default.
        // Since we use self-signed, verification might fail if we don't set up trust store context properly.
        // However, standard OpenSSL might be loose if verify locations aren't set,
        // OR it will fail. Let's see.
        // If it fails, we might need to add `SSL_CTX_set_default_verify_paths` or allow ignoring errors.
        // Current implementation of SecureSocketOpenSSLAsync doesn't expose verifyMode easily yet.
        // Let's rely on the fact that without CA configurations, OpenSSL might not verify,
        // or we expect failure `SSL_do_handshake result!=1`.

        final client = await SecureSocketOpenSslAsync.connect(
          '127.0.0.1',
          port,
          eagerHandshake: true,
        );

        await client.send(Uint8List.fromList('Ping'.codeUnits));

        final responseBytes = await client.recv(1024);
        final response = String.fromCharCodes(responseBytes);
        expect(response, equals('Pong'));

        await client.close();
        completer.complete();
      } catch (e) {
        completer.completeError(e);
      } finally {
        await serverSocket.close();
      }

      await completer.future;
    });

    test('Parallel requests handled correctly', () async {
      final serverSocket = await ServerSocket.bind('127.0.0.1', 0);
      final port = serverSocket.port;

      serverSocket.listen((clientSocket) async {
        final secureSocket = SecureSocketOpenSslAsync.serverFromSocket(
            clientSocket,
            certFile: certPath,
            keyFile: keyPath);
        final data = await secureSocket.recv(100);
        await secureSocket.send(data); // Echo
        await secureSocket.close();
      });

      final clients = <Future>[];
      for (int i = 0; i < 5; i++) {
        clients.add(Future(() async {
          final socket =
              await SecureSocketOpenSslAsync.connect('127.0.0.1', port);
          final msg = 'Msg$i';
          await socket.send(Uint8List.fromList(msg.codeUnits));
          final echo = await socket.recv(100);
          expect(String.fromCharCodes(echo), equals(msg));
          await socket.close();
        }));
      }

      await Future.wait(clients);
      await serverSocket.close();
    });
  });
}
