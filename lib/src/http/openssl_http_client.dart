import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../ssl/secure_socket_openssl_async.dart';

class OpenSslHttpResponse {
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;

  OpenSslHttpResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });

  String bodyAsString() => String.fromCharCodes(body);
}

class OpenSslHttpClient {
  Future<OpenSslHttpResponse> get(
    Uri uri, {
    Duration timeout = const Duration(seconds: 5),
    Map<String, String> headers = const {},
  }) async {
    if (uri.scheme == 'http') {
      return _getHttp(uri, timeout: timeout, headers: headers);
    }
    if (uri.scheme == 'https') {
      return _getHttps(uri, timeout: timeout, headers: headers);
    }
    throw ArgumentError('Unsupported scheme: ${uri.scheme}');
  }

  Future<OpenSslHttpResponse> _getHttp(
    Uri uri, {
    required Duration timeout,
    required Map<String, String> headers,
  }) async {
    final port = uri.hasPort ? uri.port : 80;
    final socket = await Socket.connect(uri.host, port, timeout: timeout);

    final request = _buildRequest(uri, headers: headers);
    socket.add(request);
    await socket.flush();

    final builder = BytesBuilder(copy: false);
    try {
      await socket.fold(builder, (b, data) {
        b.add(data);
        return b;
      });
    } finally {
      await socket.close();
    }

    final bytes = builder.takeBytes();
    return _parseResponse(bytes);
  }

  Future<OpenSslHttpResponse> _getHttps(
    Uri uri, {
    required Duration timeout,
    required Map<String, String> headers,
  }) async {
    final port = uri.hasPort ? uri.port : 443;
    final socket = await SecureSocketOpenSslAsync.connect(
      uri.host,
      port,
      timeout: timeout,
      eagerHandshake: true,
    );

    final request = _buildRequest(uri, headers: headers);
    await socket.send(Uint8List.fromList(request));

    final headerBytes = BytesBuilder(copy: false);
    Uint8List? bodyPrefix;

    while (true) {
      final chunk = await socket.recv(4096).timeout(timeout);
      headerBytes.add(chunk);
      final current = headerBytes.toBytes();
      final headerEnd = _indexOfHeaderEnd(current);
      if (headerEnd != -1) {
        final bodyStart = headerEnd + 4;
        if (current.length > bodyStart) {
          bodyPrefix = current.sublist(bodyStart);
        }
        final headerPart = current.sublist(0, headerEnd);
        final parsed = _parseHeaderOnly(headerPart);

        final contentLength = int.tryParse(parsed.headers['content-length'] ?? '');
        if (contentLength == null) {
          await socket.close();
          throw UnsupportedError('HTTPS response without Content-Length.');
        }

        final remaining = contentLength - (bodyPrefix?.length ?? 0);
        Uint8List body;
        if (remaining > 0) {
          final rest = await socket.recvExact(remaining).timeout(timeout);
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

        await socket.close();
        return OpenSslHttpResponse(
          statusCode: parsed.statusCode,
          headers: parsed.headers,
          body: body,
        );
      }
    }
  }

  List<int> _buildRequest(Uri uri, {required Map<String, String> headers}) {
    final path = uri.hasQuery ? '${uri.path}?${uri.query}' : uri.path;
    final requestHeaders = <String, String>{
      'Host': uri.host,
      'Connection': 'close',
      'Accept': '*/*',
      ...headers,
    };

    final buffer = StringBuffer();
    buffer.write('GET ${path.isEmpty ? '/' : path} HTTP/1.1\r\n');
    requestHeaders.forEach(
      (key, value) => buffer.write('$key: $value\r\n'),
    );
    buffer.write('\r\n');
    return Uint8List.fromList(buffer.toString().codeUnits);
  }

  OpenSslHttpResponse _parseResponse(Uint8List bytes) {
    final headerEnd = _indexOfHeaderEnd(bytes);
    if (headerEnd == -1) {
      throw FormatException('Invalid HTTP response (missing headers).');
    }

    final headerPart = bytes.sublist(0, headerEnd);
    final bodyStart = headerEnd + 4;
    final body = bodyStart < bytes.length ? bytes.sublist(bodyStart) : Uint8List(0);

    final parsed = _parseHeaderOnly(headerPart);
    return OpenSslHttpResponse(
      statusCode: parsed.statusCode,
      headers: parsed.headers,
      body: body,
    );
  }

  _ParsedHeaders _parseHeaderOnly(Uint8List headerPart) {
    final headerText = String.fromCharCodes(headerPart);
    final lines = headerText.split('\r\n');
    if (lines.isEmpty) {
      throw FormatException('Invalid HTTP response (empty header).');
    }

    final statusLine = lines.first;
    final statusPieces = statusLine.split(' ');
    if (statusPieces.length < 2) {
      throw FormatException('Invalid HTTP status line: $statusLine');
    }

    final statusCode = int.tryParse(statusPieces[1]) ?? 0;
    final headers = <String, String>{};

    for (final line in lines.skip(1)) {
      if (line.trim().isEmpty) continue;
      final index = line.indexOf(':');
      if (index <= 0) continue;
      final name = line.substring(0, index).trim().toLowerCase();
      final value = line.substring(index + 1).trim();
      headers[name] = value;
    }

    return _ParsedHeaders(statusCode, headers);
  }

  int _indexOfHeaderEnd(Uint8List data) {
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
}

class _ParsedHeaders {
  final int statusCode;
  final Map<String, String> headers;

  _ParsedHeaders(this.statusCode, this.headers);
}
