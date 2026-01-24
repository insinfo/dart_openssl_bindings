import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('OpenSslHttpClient', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('http get against local server', () async {
      final server = await OpenSslHttpServer.bindHttp(
        handler: (request) {
          return OpenSslHttpResponseData(
            statusCode: 200,
            body: Uint8List.fromList('hello-http'.codeUnits),
          );
        },
      );

      final client = OpenSslHttpClient();
      try {
        final response = await client.get(
          Uri.parse('http://127.0.0.1:${server.port}/'),
        );
        expect(response.statusCode, equals(200));
        expect(response.bodyAsString(), equals('hello-http'));
      } finally {
        await server.close();
      }
    });

    test('https get against secure socket server', () async {
      const handshakeTimeout = Duration(seconds: 5);
      const ioTimeout = Duration(seconds: 5);

      final key = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'HTTPS Test');
      builder.setIssuerAsSubject();
      builder.setPublicKey(key);
      builder.setValidity(notAfterOffset: 600);
      final cert = builder.sign(key);

      final tempDir = await Directory.systemTemp.createTemp('openssl_https_');
      final certFile = File('${tempDir.path}/cert.pem');
      final keyFile = File('${tempDir.path}/key.pem');
      await certFile.writeAsString(cert.toPem());
      await keyFile.writeAsString(key.toPrivateKeyPem());

      final server = await OpenSslHttpServer.bindHttps(
        certFile: certFile.path,
        keyFile: keyFile.path,
        handshakeTimeout: handshakeTimeout,
        handler: (request) {
          return OpenSslHttpResponseData(
            statusCode: 200,
            body: Uint8List.fromList('hello-https'.codeUnits),
          );
        },
      );

      final client = OpenSslHttpClient();
      try {
        final response = await client
            .get(Uri.parse('https://127.0.0.1:${server.port}/'))
            .timeout(ioTimeout);
        expect(response.statusCode, equals(200));
        expect(response.bodyAsString(), equals('hello-https'));
      } finally {
        await server.close();
        await tempDir.delete(recursive: true);
      }
    });

    test('https server handles concurrent requests', () async {
      const handshakeTimeout = Duration(seconds: 5);
      const ioTimeout = Duration(seconds: 8);

      final key = openSsl.generateRsa(2048);
      final builder = openSsl.newCertificateBuilder();
      builder.setSubject(commonName: 'HTTPS Concurrency Test');
      builder.setIssuerAsSubject();
      builder.setPublicKey(key);
      builder.setValidity(notAfterOffset: 600);
      final cert = builder.sign(key);

      final tempDir = await Directory.systemTemp.createTemp('openssl_https_');
      final certFile = File('${tempDir.path}/cert.pem');
      final keyFile = File('${tempDir.path}/key.pem');
      await certFile.writeAsString(cert.toPem());
      await keyFile.writeAsString(key.toPrivateKeyPem());

      final server = await OpenSslHttpServer.bindHttps(
        certFile: certFile.path,
        keyFile: keyFile.path,
        handshakeTimeout: handshakeTimeout,
        handler: (request) {
          final path = request.uri.path.isEmpty ? '/' : request.uri.path;
          return OpenSslHttpResponseData(
            statusCode: 200,
            body: Uint8List.fromList('ok:$path'.codeUnits),
          );
        },
      );

      final client = OpenSslHttpClient();
      try {
        final futures = List.generate(6, (i) {
          final path = '/r${i + 1}';
          final uri = Uri.parse('https://127.0.0.1:${server.port}$path');
          return client.get(uri).timeout(ioTimeout).then((response) {
            expect(response.statusCode, equals(200));
            expect(response.bodyAsString(), equals('ok:$path'));
          });
        });

        await Future.wait(futures);
      } finally {
        await server.close();
        await tempDir.delete(recursive: true);
      }
    });
  });
}
