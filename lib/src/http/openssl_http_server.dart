import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../ssl/secure_socket_openssl_async.dart';

typedef OpenSslHttpHandler = FutureOr<OpenSslHttpResponseData> Function(
  OpenSslHttpRequest request,
);

class OpenSslHttpRequest {
  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final Uint8List body;

  OpenSslHttpRequest({
    required this.method,
    required this.uri,
    required this.headers,
    required this.body,
  });
}

class OpenSslHttpResponseData {
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;

  OpenSslHttpResponseData({
    required this.statusCode,
    this.headers = const {},
    Uint8List? body,
  }) : body = body ?? Uint8List(0);
}

class OpenSslHttpServer {
  OpenSslHttpServer._({
    required String host,
    required int port,
    required bool isHttps,
    HttpServer? httpServer,
    ServerSocket? serverSocket,
  })  : _host = host,
        _port = port,
        _isHttps = isHttps,
        _httpServer = httpServer,
        _serverSocket = serverSocket;

  final String _host;
  final int _port;
  final bool _isHttps;
  final HttpServer? _httpServer;
  final ServerSocket? _serverSocket;

  String get host => _host;
  int get port => _port;
  bool get isHttps => _isHttps;

  static Future<OpenSslHttpServer> bindHttp({
    String host = '127.0.0.1',
    int port = 0,
    bool shared = false,
    int backlog = 0,
    required OpenSslHttpHandler handler,
  }) async {
    final server = backlog > 0
        ? await HttpServer.bind(
            host,
            port,
            shared: shared,
            backlog: backlog,
          )
        : await HttpServer.bind(
            host,
            port,
            shared: shared,
          );
    server.listen((request) async {
      try {
        final body = await _readHttpBody(request);
        final headers = <String, String>{};
        request.headers.forEach((name, values) {
          headers[name.toLowerCase()] = values.join(',');
        });

        final data = OpenSslHttpRequest(
          method: request.method,
          uri: request.uri,
          headers: headers,
          body: body,
        );
        final response = await handler(data);
        await _writeHttpResponse(request.response, response);
      } catch (error) {
        await _writeHttpResponse(
          request.response,
          OpenSslHttpResponseData(
            statusCode: 500,
            body: Uint8List.fromList('internal error'.codeUnits),
          ),
        );
      }
    });

    return OpenSslHttpServer._(
      host: server.address.host,
      port: server.port,
      isHttps: false,
      httpServer: server,
    );
  }

  static Future<OpenSslHttpServer> bindHttps({
    String host = '127.0.0.1',
    int port = 0,
    bool shared = false,
    int backlog = 0,
    required String certFile,
    required String keyFile,
    required OpenSslHttpHandler handler,
    Duration handshakeTimeout = const Duration(seconds: 5),
  }) async {
    final serverSocket = await ServerSocket.bind(
      host,
      port,
      shared: shared,
      backlog: backlog,
    );

    serverSocket.listen((socket) async {
      final secure = SecureSocketOpenSslAsync.serverFromSocket(
        socket,
        certFile: certFile,
        keyFile: keyFile,
        eagerHandshake: true,
      );

      var handshakeOk = false;

      try {
        await secure.ensureHandshakeCompleted().timeout(handshakeTimeout);
        handshakeOk = true;
        final request = await _readHttpsRequest(secure);
        final response = await handler(request);
        await _writeHttpsResponse(secure, response);
      } catch (_) {
        if (handshakeOk) {
          try {
            await _writeHttpsResponse(
              secure,
              OpenSslHttpResponseData(
                statusCode: 500,
                body: Uint8List.fromList('internal error'.codeUnits),
              ),
            );
          } catch (_) {
            // ignore write errors after handshake failure
          }
        }
      } finally {
        await secure.close();
      }
    });

    return OpenSslHttpServer._(
      host: serverSocket.address.address,
      port: serverSocket.port,
      isHttps: true,
      serverSocket: serverSocket,
    );
  }

  Future<void> close() async {
    await _httpServer?.close(force: true);
    await _serverSocket?.close();
  }

  static Future<Uint8List> _readHttpBody(HttpRequest request) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in request) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  }

  static Future<OpenSslHttpRequest> _readHttpsRequest(
    SecureSocketOpenSslAsync socket,
  ) async {
    final headerBytes = BytesBuilder(copy: false);
    Uint8List? bodyPrefix;

    while (true) {
      final chunk = await socket.recv(4096);
      headerBytes.add(chunk);
      final current = headerBytes.toBytes();
      final headerEnd = _indexOfHeaderEnd(current);
      if (headerEnd == -1) {
        continue;
      }

      final headerPart = current.sublist(0, headerEnd);
      final bodyStart = headerEnd + 4;
      if (current.length > bodyStart) {
        bodyPrefix = current.sublist(bodyStart);
      }

      final headerText = String.fromCharCodes(headerPart);
      final lines = headerText.split('\r\n');
      if (lines.isEmpty) {
        throw FormatException('Invalid HTTP request');
      }

      final requestLine = lines.first.split(' ');
      if (requestLine.length < 2) {
        throw FormatException('Invalid request line');
      }

      final method = requestLine[0].trim().toUpperCase();
      final path = requestLine[1].trim();
      final headers = <String, String>{};
      for (final line in lines.skip(1)) {
        if (line.trim().isEmpty) continue;
        final idx = line.indexOf(':');
        if (idx <= 0) continue;
        final name = line.substring(0, idx).trim().toLowerCase();
        final value = line.substring(idx + 1).trim();
        headers[name] = value;
      }

      final contentLength = int.tryParse(headers['content-length'] ?? '') ?? 0;
      final remaining = contentLength - (bodyPrefix?.length ?? 0);
      Uint8List body;
      if (remaining > 0) {
        final rest = await socket.recvExact(remaining);
        if (bodyPrefix == null || bodyPrefix.isEmpty) {
          body = rest;
        } else {
          final merged = BytesBuilder(copy: false)
            ..add(bodyPrefix)
            ..add(rest);
          body = merged.takeBytes();
        }
      } else {
        body = bodyPrefix ?? Uint8List(0);
      }

      return OpenSslHttpRequest(
        method: method,
        uri: Uri.parse(path),
        headers: headers,
        body: body,
      );
    }
  }

  static Future<void> _writeHttpResponse(
    HttpResponse response,
    OpenSslHttpResponseData data,
  ) async {
    response.statusCode = data.statusCode;
    response.headers.set('Content-Length', data.body.length.toString());
    response.headers.set('Connection', 'close');
    data.headers.forEach((key, value) {
      response.headers.set(key, value);
    });
    response.add(data.body);
    await response.close();
  }

  static Future<void> _writeHttpsResponse(
    SecureSocketOpenSslAsync socket,
    OpenSslHttpResponseData response,
  ) async {
    final reason = _reasonPhrase(response.statusCode);
    final headers = <String, String>{
      'Content-Length': response.body.length.toString(),
      'Connection': 'close',
      ...response.headers,
    };

    final buffer = StringBuffer();
    buffer.write('HTTP/1.1 ${response.statusCode} $reason\r\n');
    headers.forEach((key, value) => buffer.write('$key: $value\r\n'));
    buffer.write('\r\n');

    final headerBytes = Uint8List.fromList(buffer.toString().codeUnits);
    await socket.send(headerBytes);
    if (response.body.isNotEmpty) {
      await socket.send(response.body);
    }
  }

  static int _indexOfHeaderEnd(Uint8List data) {
    for (var i = 0; i + 3 < data.length; i++) {
      if (data[i] == 13 &&
          data[i + 1] == 10 &&
          data[i + 2] == 13 &&
          data[i + 3] == 10) {
        return i;
      }
    }
    return -1;
  }

  static String _reasonPhrase(int statusCode) {
    switch (statusCode) {
      case 200:
        return 'OK';
      case 201:
        return 'Created';
      case 204:
        return 'No Content';
      case 400:
        return 'Bad Request';
      case 404:
        return 'Not Found';
      case 500:
        return 'Internal Server Error';
      default:
        return 'OK';
    }
  }
}
