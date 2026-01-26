import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

// dart compile exe .\script\stress_sign_server.dart  --output .\script\stress_sign_server.exe
// 
// Único isolate:
// dart run stress_sign_server.dart --host=127.0.0.1 --port=8080 --multithread=false
// Multi‑isolates:
// dart run stress_sign_server.dart --host=127.0.0.1 --port=8080 --multithread=true --isolates=4


void main(List<String> args) async {
  final mode = args.isNotEmpty ? args.first.toLowerCase() : 'server';
  if (mode == 'load') {
    await _runLoad(args.skip(1).toList());
    return;
  }

  await _runServer(args);
}

Future<void> _runServer(List<String> args) async {
  final host = _argValue(args, '--host') ?? '127.0.0.1';
  final port = int.tryParse(_argValue(args, '--port') ?? '') ?? 8080;
  final keyBits = int.tryParse(_argValue(args, '--key-bits') ?? '') ?? 2048;
  final isolates = int.tryParse(_argValue(args, '--isolates') ?? '') ?? 1;
  final multithread = _argBool(args, '--multithread', defaultValue: true);

  final config = _ServerConfig(
    host: host,
    port: port,
    keyBits: keyBits,
    isolates: isolates,
    enableMultiThread: multithread,
  );

  if (!config.enableMultiThread || config.isolates <= 1) {
    await _startServer(config);
    return;
  }

  for (var i = 0; i < config.isolates - 1; i++) {
    final clone = config.copyWith(id: i);
    await Isolate.spawn(_isolateMain, clone, debugName: 'stress-${clone.id}');
  }

  final last = config.copyWith(id: config.isolates - 1);
  await _startServer(last);
}

Future<void> _isolateMain(_ServerConfig config) async {
  await _startServer(config);
}

Future<void> _startServer(_ServerConfig config) async {
  final server = _SignServer(
    keyBits: config.keyBits,
  );
  await server.initialize();
  final httpServer = await HttpServer.bind(
    config.host,
    config.port,
    shared: config.enableMultiThread,
  );
  if (config.id == 0 || !config.enableMultiThread) {
    print('[stress] server on http://${config.host}:${httpServer.port}');
    print('[stress] endpoints:');
    print('  GET  /health');
    print('  GET  /cert');
    print('  POST /issue');
    print('  POST /sign');
    if (config.enableMultiThread) {
      print('[stress] multithread isolates=${config.isolates}');
    }
  } else {
    print('[stress] isolate ${config.id} online');
  }

  await for (final request in httpServer) {
    unawaited(server.handle(request));
  }
}

class _ServerConfig {
  _ServerConfig({
    required this.host,
    required this.port,
    required this.keyBits,
    required this.isolates,
    required this.enableMultiThread,
    this.id = 0,
  });

  final String host;
  final int port;
  final int keyBits;
  final int isolates;
  final bool enableMultiThread;
  final int id;

  _ServerConfig copyWith({int? id}) {
    return _ServerConfig(
      host: host,
      port: port,
      keyBits: keyBits,
      isolates: isolates,
      enableMultiThread: enableMultiThread,
      id: id ?? this.id,
    );
  }
}

Future<void> _runLoad(List<String> args) async {
  final baseUrl = _argValue(args, '--url') ?? 'http://127.0.0.1:8080';
  final total = int.tryParse(_argValue(args, '--total') ?? '') ?? 2000;
  final concurrency = int.tryParse(_argValue(args, '--concurrency') ?? '') ?? 50;
  final hashSize = int.tryParse(_argValue(args, '--hash-size') ?? '') ?? 32;
  final seed = int.tryParse(_argValue(args, '--seed') ?? '') ?? 0;

  final uri = Uri.parse(baseUrl).resolve('/sign');
  final client = HttpClient();
  client.connectionTimeout = const Duration(seconds: 15);

  final rng = seed == 0 ? Random.secure() : Random(seed);
  final sem = _Semaphore(concurrency);
  var success = 0;
  var failed = 0;

  final start = DateTime.now();
  final progressTimer = Timer.periodic(const Duration(seconds: 2), (_) {
    final rss = ProcessInfo.currentRss / (1024 * 1024);
    final elapsed = DateTime.now().difference(start).inSeconds;
    print('[load] ok=$success fail=$failed rss=${rss.toStringAsFixed(1)}MB t=${elapsed}s');
  });

  Future<void> sendOne(int idx) async {
    await sem.acquire();
    try {
      final hash = Uint8List.fromList(List<int>.generate(hashSize, (_) => rng.nextInt(256)));
      final payload = jsonEncode({'hashBase64': base64Encode(hash)});

      final request = await client.postUrl(uri);
      request.headers.contentType = ContentType.json;
      request.write(payload);

      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();

      if (response.statusCode == 200) {
        final decoded = jsonDecode(body) as Map<String, dynamic>;
        if ((decoded['cmsBase64'] as String?)?.isNotEmpty == true) {
          success++;
        } else {
          failed++;
        }
      } else {
        failed++;
      }
    } catch (_) {
      failed++;
    } finally {
      sem.release();
    }
  }

  final futures = <Future<void>>[];
  for (var i = 0; i < total; i++) {
    futures.add(sendOne(i));
  }

  await Future.wait(futures);
  progressTimer.cancel();
  client.close(force: true);

  final elapsed = DateTime.now().difference(start);
  final rss = ProcessInfo.currentRss / (1024 * 1024);
  print('[load] finished ok=$success fail=$failed time=${elapsed.inSeconds}s rss=${rss.toStringAsFixed(1)}MB');
}

class _SignServer {
  _SignServer({required this.keyBits});

  final int keyBits;
  late final OpenSSL _openssl;
  late final EvpPkey _signKey;
  late final X509Certificate _signCert;
  late final Uint8List _signCertDer;
  late final CmsPkcs7Signer _signer;
  final DateTime _startedAt = DateTime.now();
  int _requestCount = 0;

  Future<void> initialize() async {
    _openssl = OpenSSL();
    _signer = CmsPkcs7Signer(_openssl);
    await _generateSigner();
  }

  Future<void> _generateSigner() async {
    _signKey = _openssl.generateRsa(keyBits);

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

  Future<void> handle(HttpRequest request) async {
    _requestCount++;
    try {
      final path = request.uri.path;
      if (path == '/health') {
        _writeText(request, 200, 'ok');
        return;
      }
      if (path == '/metrics') {
        _writeJson(request, 200, _metricsPayload());
        return;
      }
      if (path == '/cert' && request.method == 'GET') {
        _writeText(request, 200, _signCert.toPem(), contentType: ContentType('application', 'x-pem-file'));
        return;
      }
      if (path == '/issue' && request.method == 'POST') {
        final keyBits = int.tryParse(request.uri.queryParameters['bits'] ?? '') ?? 2048;
        final result = _issueCertificate(bits: keyBits);
        _writeJson(request, 200, result);
        return;
      }
      if (path == '/sign' && request.method == 'POST') {
        final body = await _readJson(request);
        final hashBase64 = body['hashBase64']?.toString();
        final dataBase64 = body['dataBase64']?.toString();

        Uint8List digest;
        if (hashBase64 != null && hashBase64.isNotEmpty) {
          digest = Uint8List.fromList(base64Decode(hashBase64));
        } else if (dataBase64 != null && dataBase64.isNotEmpty) {
          final data = Uint8List.fromList(base64Decode(dataBase64));
          digest = _openssl.digest('sha256', data);
        } else {
          _writeJson(request, 400, {'error': 'hashBase64 ou dataBase64 é obrigatório'});
          return;
        }

        final cms = _signer.signDetachedDigest(
          contentDigest: digest,
          certificateDer: _signCertDer,
          privateKey: _signKey,
          hashAlgorithm: 'SHA256',
        );

        _writeJson(request, 200, {
          'cmsBase64': base64Encode(cms),
          'certPem': _signCert.toPem(),
        });
        return;
      }

      _writeJson(request, 404, {'error': 'not_found'});
    } catch (e) {
      _writeJson(request, 500, {'error': 'internal_error', 'message': e.toString()});
    }
  }

  Map<String, dynamic> _issueCertificate({required int bits}) {
    final key = _openssl.generateRsa(bits);
    final serial = _randomSerial();

    final builder = X509CertificateBuilder(_openssl)
      ..setSerialNumber(serial)
      ..setSubject(
        commonName: 'Issued Cert $serial',
        organization: 'openssl_bindings',
        country: 'BR',
      )
      ..setIssuerAsSubject()
      ..setPublicKey(key)
      ..setValidity(notBeforeOffset: 0, notAfterOffset: 365 * 86400)
      ..addBasicConstraints(isCa: false, critical: true)
      ..addKeyUsage(digitalSignature: true, keyEncipherment: true, critical: true);

    final cert = builder.sign(key, hashAlgorithm: 'SHA256');

    return {
      'certPem': cert.toPem(),
      'privateKeyPem': key.toPrivateKeyPem(),
      'serial': serial.toString(),
    };
  }

  int _randomSerial() {
    final rng = Random.secure();
    return 2 + rng.nextInt(0x7FFFFFFF - 2);
  }

  Map<String, dynamic> _metricsPayload() {
    final uptime = DateTime.now().difference(_startedAt);
    final rss = ProcessInfo.currentRss / (1024 * 1024);
    return {
      'requests': _requestCount,
      'rss_mb': double.parse(rss.toStringAsFixed(2)),
      'uptime_ms': uptime.inMilliseconds,
    };
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

void _writeText(HttpRequest req, int status, String body, {ContentType? contentType}) {
  req.response.statusCode = status;
  if (contentType != null) {
    req.response.headers.contentType = contentType;
  } else {
    req.response.headers.contentType = ContentType.text;
  }
  req.response.write(body);
  req.response.close();
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

String? _argValue(List<String> args, String name) {
  for (final arg in args) {
    if (arg.startsWith('$name=')) {
      return arg.substring(name.length + 1).trim();
    }
  }
  return null;
}

bool _argBool(List<String> args, String name, {required bool defaultValue}) {
  final value = _argValue(args, name);
  if (value == null) return defaultValue;
  final normalized = value.toLowerCase();
  if (normalized == 'true' || normalized == '1' || normalized == 'yes') {
    return true;
  }
  if (normalized == 'false' || normalized == '0' || normalized == 'no') {
    return false;
  }
  return defaultValue;
}
