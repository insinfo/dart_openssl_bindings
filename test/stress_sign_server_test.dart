import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  test('stress sign server handles concurrent requests', () async {
    final server = _InMemorySignServer();
    await server.start();

    try {
      final baseUri = server.baseUri;
      final uri = baseUri.resolve('/sign');

      const total = 200;
      const concurrency = 20;
      const hashSize = 32;

      final rng = Random.secure();
      final sem = _Semaphore(concurrency);
      final client = HttpClient();

      var ok = 0;
      var fail = 0;

      Future<void> sendOne() async {
        await sem.acquire();
        try {
          final hash = Uint8List.fromList(
            List<int>.generate(hashSize, (_) => rng.nextInt(256)),
          );
          final payload = jsonEncode({'hashBase64': base64Encode(hash)});

          final request = await client.postUrl(uri);
          request.headers.contentType = ContentType.json;
          request.write(payload);

          final response = await request.close();
          final body = await response.transform(utf8.decoder).join();

          if (response.statusCode != 200) {
            fail++;
            return;
          }

          final decoded = jsonDecode(body) as Map<String, dynamic>;
          final cmsBase64 = decoded['cmsBase64']?.toString() ?? '';
          if (cmsBase64.isEmpty) {
            fail++;
            return;
          }
          base64Decode(cmsBase64);
          ok++;
        } catch (_) {
          fail++;
        } finally {
          sem.release();
        }
      }

      final futures = List.generate(total, (_) => sendOne());
      await Future.wait(futures);

      client.close(force: true);

      expect(fail, 0);
      expect(ok, total);
    } finally {
      await server.stop();
    }
  });
}

class _InMemorySignServer {
  late final OpenSSL _openssl;
  late final EvpPkey _signKey;
  late final X509Certificate _signCert;
  late final Uint8List _signCertDer;
  late final CmsPkcs7Signer _signer;

  HttpServer? _server;

  Uri get baseUri {
    final server = _server;
    if (server == null) {
      throw StateError('Server not started');
    }
    return Uri.parse('http://${server.address.host}:${server.port}');
  }

  Future<void> start() async {
    _openssl = OpenSSL();
    _signer = CmsPkcs7Signer(_openssl);
    await _generateSigner();

    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _server!.listen(_handle);
  }

  Future<void> stop() async {
    final server = _server;
    if (server != null) {
      await server.close(force: true);
    }
  }

  Future<void> _generateSigner() async {
    _signKey = _openssl.generateRsa(2048);

    final serial = _randomSerial();
    final builder = X509CertificateBuilder(_openssl)
      ..setSerialNumber(serial)
      ..setSubject(
        commonName: 'Stress Signer',
        organization: 'openssl_bindings',
        country: 'BR',
      )
      ..setIssuerAsSubject()
      ..setPublicKey(_signKey)
      ..setValidity(notBeforeOffset: 0, notAfterOffset: 365 * 86400)
      ..addBasicConstraints(isCa: false, critical: true)
      ..addKeyUsage(digitalSignature: true, keyEncipherment: true, critical: true);

    _signCert = builder.sign(_signKey, hashAlgorithm: 'SHA256');
    _signCertDer = _signCert.toDer();
  }

  Future<void> _handle(HttpRequest request) async {
    try {
      if (request.uri.path != '/sign' || request.method != 'POST') {
        _writeJson(request, 404, {'error': 'not_found'});
        return;
      }

      final body = await _readJson(request);
      final hashBase64 = body['hashBase64']?.toString();
      if (hashBase64 == null || hashBase64.isEmpty) {
        _writeJson(request, 400, {'error': 'hashBase64 requerido'});
        return;
      }

      final digest = Uint8List.fromList(base64Decode(hashBase64));

      final cms = _signer.signDetachedDigest(
        contentDigest: digest,
        certificateDer: _signCertDer,
        privateKey: _signKey,
        hashAlgorithm: 'SHA256',
      );

      _writeJson(request, 200, {'cmsBase64': base64Encode(cms)});
    } catch (e) {
      _writeJson(request, 500, {'error': e.toString()});
    }
  }

  int _randomSerial() {
    final rng = Random.secure();
    return 2 + rng.nextInt(0x7FFFFFFF - 2);
  }
}

class _Semaphore {
  _Semaphore(this._available);

  int _available;
  final List<Completer<void>> _queue = [];

  Future<void> acquire() {
    if (_available > 0) {
      _available--;
      return Future.value();
    }
    final completer = Completer<void>();
    _queue.add(completer);
    return completer.future;
  }

  void release() {
    if (_queue.isNotEmpty) {
      _queue.removeAt(0).complete();
      return;
    }
    _available++;
  }
}

void _writeJson(HttpRequest req, int status, Map<String, dynamic> body) {
  req.response.statusCode = status;
  req.response.headers.contentType = ContentType.json;
  req.response.write(jsonEncode(body));
  req.response.close();
}

Future<Map<String, dynamic>> _readJson(HttpRequest req) async {
  final body = await utf8.decoder.bind(req).join();
  if (body.trim().isEmpty) return const {};
  final decoded = jsonDecode(body);
  if (decoded is Map) {
    return Map<String, dynamic>.from(decoded);
  }
  return const {};
}
