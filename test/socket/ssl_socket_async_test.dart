import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

import 'package:test/test.dart';

void main() {
  group('SecureSocketOpenSSLAsync', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test(
      'handshake and bidirectional data exchange',
      () async {
        const handshakeTimeout = Duration(seconds: 5);
        const ioTimeout = Duration(seconds: 5);

        SecureSocketOpenSslAsync? client;
        SecureSocketOpenSslAsync? serverSecure;
        ServerSocket? server;
        Directory? tempDir;

        addTearDown(() async {
          await client?.close();
          await serverSecure?.close();
          await server?.close();
          if (tempDir != null) {
            await tempDir.delete(recursive: true);
          }
        });

        final key = openSsl.generateRsa(2048);
        final builder = openSsl.newCertificateBuilder();
        builder.setSubject(commonName: 'TLS Test');
        builder.setIssuerAsSubject();
        builder.setPublicKey(key);
        builder.setValidity(notAfterOffset: 600);

        final cert = builder.sign(key);

        tempDir = await Directory.systemTemp.createTemp('openssl_bindings_');
        final certFile = File('${tempDir.path}/cert.pem');
        final keyFile = File('${tempDir.path}/key.pem');
        await certFile.writeAsString(cert.toPem());
        await keyFile.writeAsString(key.toPrivateKeyPem());

        server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        final serverReady = Completer<SecureSocketOpenSslAsync>();

        server.listen(
          (socket) async {
            try {
              serverSecure = SecureSocketOpenSslAsync.serverFromSocket(
                socket,
                certFile: certFile.path,
                keyFile: keyFile.path,
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

        await client.send(Uint8List.fromList(utf8.encode('ping')));
        final serverData =
            await serverSecure!.recvExact(4).timeout(ioTimeout);
        expect(utf8.decode(serverData), equals('ping'));

        await serverSecure!.send(Uint8List.fromList(utf8.encode('pong')));
        final clientData = await client.recvExact(4).timeout(ioTimeout);
        expect(utf8.decode(clientData), equals('pong'));
      },
      timeout: Timeout(Duration(seconds: 15)),
    );
  });
}
