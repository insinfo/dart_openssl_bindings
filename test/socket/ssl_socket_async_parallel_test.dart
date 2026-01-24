import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

import 'package:test/test.dart';

void main() {
  group('SecureSocketOpenSSLAsync (parallel instances)', () {
    late OpenSSL openSsl;
    late Directory tempDir;
    late String certPath;
    late String keyPath;

    setUpAll(() async {
      openSsl = OpenSSL();
      final key = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'TLS Parallel Test');
      builder.setIssuerAsSubject();
      builder.setPublicKey(key);
      builder.setValidity(notAfterOffset: 600);
      final cert = builder.sign(key);

      tempDir = await Directory.systemTemp.createTemp('openssl_parallel_');
      certPath = '${tempDir.path}/cert.pem';
      keyPath = '${tempDir.path}/key.pem';
      await File(certPath).writeAsString(cert.toPem());
      await File(keyPath).writeAsString(key.toPrivateKeyPem());
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    Future<void> _runSession(int id) async {
      const handshakeTimeout = Duration(seconds: 5);
      const ioTimeout = Duration(seconds: 5);

      SecureSocketOpenSslAsync? client;
      SecureSocketOpenSslAsync? serverSecure;
      ServerSocket? server;

      try {
        server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        final serverReady = Completer<SecureSocketOpenSslAsync>();

        server.listen(
          (socket) async {
            try {
              serverSecure = SecureSocketOpenSslAsync.serverFromSocket(
                socket,
                certFile: certPath,
                keyFile: keyPath,
                eagerHandshake: true,
              );
              await serverSecure!
                  .ensureHandshakeCompleted()
                  .timeout(handshakeTimeout);
              if (!serverReady.isCompleted) {
                serverReady.complete(serverSecure);
              }
            } catch (error, stackTrace) {
              if (!serverReady.isCompleted) {
                serverReady.completeError(error, stackTrace);
              }
            }
          },
          onError: (error, stackTrace) {
            if (!serverReady.isCompleted) {
              serverReady.completeError(error, stackTrace);
            }
          },
          cancelOnError: true,
        );

        client = await SecureSocketOpenSslAsync.connect(
          InternetAddress.loopbackIPv4.address,
          server.port,
          timeout: handshakeTimeout,
          eagerHandshake: true,
        );

        await client.ensureHandshakeCompleted().timeout(handshakeTimeout);
        serverSecure = await serverReady.future.timeout(handshakeTimeout);

        final ping = 'ping-$id';
        final pong = 'pong-$id';

        await client.send(Uint8List.fromList(utf8.encode(ping)));
        final serverData =
            await serverSecure!.recvExact(ping.length).timeout(ioTimeout);
        expect(utf8.decode(serverData), equals(ping));

        await serverSecure!.send(Uint8List.fromList(utf8.encode(pong)));
        final clientData =
            await client.recvExact(pong.length).timeout(ioTimeout);
        expect(utf8.decode(clientData), equals(pong));
      } finally {
        await client?.close();
        await serverSecure?.close();
        await server?.close();
      }
    }

    test(
      'multiple isolated instances in parallel',
      () async {
        await Future.wait([
          _runSession(1),
          _runSession(2),
          _runSession(3),
          _runSession(4),
        ]);
      },
      timeout: Timeout(Duration(seconds: 20)),
    );
  });
}
