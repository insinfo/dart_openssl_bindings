import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

Future<void> main(List<String> args) async {
  final config = _parseArgs(args);

  if ((config['https'] as bool) && (config['isolates'] as int) > 1) {
    final certFile = config['certFile'] as String?;
    final keyFile = config['keyFile'] as String?;
    if (certFile == null || certFile.isEmpty || keyFile == null || keyFile.isEmpty) {
      final resolved = await _resolveHttpsCredentials(
        certFile: certFile,
        keyFile: keyFile,
        tempDir: config['tempDir'] as Directory?,
      );
      config['certFile'] = resolved.certPath;
      config['keyFile'] = resolved.keyPath;
      config['tempDir'] = resolved.tempDir;
    }
  }

  final isolateCount = config['isolates'] as int;
  if (isolateCount <= 1) {
    final server = await _startServer(config);
    await _waitForShutdown(
      server: server,
      tempDir: config['tempDir'] as Directory?,
      listenToStdin: !Platform.isWindows,
    );
    return;
  }

  final readyPort = ReceivePort();
  final shutdownPorts = <SendPort>[];
  final isolates = <Isolate>[];
  final exitPort = ReceivePort();
  var readyCount = 0;

  readyPort.listen((message) {
    if (message is Map) {
      final type = message['type']?.toString();
      if (type == 'ready') {
        readyCount += 1;
        final port = message['shutdownPort'];
        if (port is SendPort) {
          shutdownPorts.add(port);
        }
        if (readyCount == isolateCount) {
          // ignore: avoid_print
          print('All isolates ready ($readyCount).');
        }
      }
    }
  });

  for (var i = 0; i < isolateCount; i++) {
    final cfg = Map<String, dynamic>.from(config)
      ..['id'] = i
      ..['readyPort'] = readyPort.sendPort
      ..['tempDir'] = null;
    final isolate = await Isolate.spawn(_isolateMain, cfg);
    isolate.addOnExitListener(exitPort.sendPort, response: i);
    isolates.add(isolate);
  }

  exitPort.listen((_) {});

  await _waitForShutdown(
    server: null,
    tempDir: config['tempDir'] as Directory?,
    onShutdown: () {
      readyPort.close();
      exitPort.close();
      for (final port in shutdownPorts) {
        port.send('shutdown');
      }
      unawaited(
        Future.delayed(const Duration(milliseconds: 250), () {
          for (final isolate in isolates) {
            isolate.kill(priority: Isolate.immediate);
          }
        }),
      );
    },
    listenToStdin: !Platform.isWindows,
  );
}

Future<OpenSslHttpServer> _startServer(Map<String, dynamic> config) async {
  final address = config['address'] as String;
  final port = config['port'] as int;
  final isHttps = config['https'] as bool;
  final shared = config['shared'] as bool;
  final certFile = config['certFile'] as String?;
  final keyFile = config['keyFile'] as String?;
  final isolateId = config['id'] as int? ?? 0;
  final tempDir = config['tempDir'] as Directory?;

  final handler = (OpenSslHttpRequest request) {
    if (request.uri.path == '/health') {
      return OpenSslHttpResponseData(
        statusCode: 200,
        headers: const {'content-type': 'text/plain'},
        body: Uint8List.fromList('ok'.codeUnits),
      );
    }

    final payload = jsonEncode({
      'method': request.method,
      'path': request.uri.path,
      'query': request.uri.query,
      'isolate': isolateId,
    });

    return OpenSslHttpResponseData(
      statusCode: 200,
      headers: const {'content-type': 'application/json'},
      body: Uint8List.fromList(payload.codeUnits),
    );
  };

  if (isHttps) {
    final resolved = await _resolveHttpsCredentials(
      certFile: certFile,
      keyFile: keyFile,
      tempDir: tempDir,
    );

    final server = await OpenSslHttpServer.bindHttps(
      host: address,
      port: port,
      shared: shared,
      certFile: resolved.certPath,
      keyFile: resolved.keyPath,
      handler: handler,
    );
    _logServer('https', server.host, server.port, isolateId);
    return server;
  } else {
    final server = await OpenSslHttpServer.bindHttp(
      host: address,
      port: port,
      shared: shared,
      handler: handler,
    );
    _logServer('http', server.host, server.port, isolateId);
    return server;
  }
}

Future<void> _isolateMain(Map<String, dynamic> config) async {
  final readyPort = config['readyPort'] as SendPort?;
  final shutdownPort = ReceivePort();
  final shutdownCompleter = Completer<void>();
  final server = await _startServer(config);
  readyPort?.send({
    'type': 'ready',
    'shutdownPort': shutdownPort.sendPort,
  });

  shutdownPort.listen((message) {
    if (message == 'shutdown' && !shutdownCompleter.isCompleted) {
      shutdownCompleter.complete();
      shutdownPort.close();
    }
  });

  await _waitForShutdown(
    server: server,
    tempDir: config['tempDir'] as Directory?,
    onShutdown: null,
    shutdownFuture: shutdownCompleter.future,
    listenToSignals: false,
    listenToStdin: false,
  );
}

void _logServer(String scheme, String host, int port, int isolateId) {
  // ignore: avoid_print
  print('[$isolateId] Listening on $scheme://$host:$port');
  if (host == '0.0.0.0') {
    // ignore: avoid_print
    print('[$isolateId] Use $scheme://localhost:$port');
  }
}

Map<String, dynamic> _parseArgs(List<String> args) {
  final config = <String, dynamic>{
    'address': '0.0.0.0',
    'port': 8080,
    'isolates': 1,
    'https': true,
    'shared': true,
    'certFile': null,
    'keyFile': null,
    'id': 0,
    'tempDir': null,
  };

  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    switch (arg) {
      case '--address':
      case '-a':
        config['address'] = _nextArg(args, ++i, arg);
        break;
      case '--port':
      case '-p':
        config['port'] = int.parse(_nextArg(args, ++i, arg));
        break;
      case '--isolates':
      case '-i':
        config['isolates'] = int.parse(_nextArg(args, ++i, arg));
        break;
      case '--isolate':
        config['isolates'] = int.parse(_nextArg(args, ++i, arg));
        break;
      case '--https':
        config['https'] = true;
        break;
      case '--http':
        config['https'] = false;
        break;
      case '--cert':
        config['certFile'] = _nextArg(args, ++i, arg);
        break;
      case '--key':
        config['keyFile'] = _nextArg(args, ++i, arg);
        break;
      case '--shared':
        config['shared'] = true;
        break;
      case '--no-shared':
        config['shared'] = false;
        break;
      default:
        break;
    }
  }

  return config;
}

Future<void> _waitForShutdown({
  OpenSslHttpServer? server,
  Directory? tempDir,
  void Function()? onShutdown,
  Future<void>? shutdownFuture,
  bool listenToSignals = true,
  bool listenToStdin = true,
}) async {
  var closing = false;
  Timer? forceExitTimer;
  StreamSubscription<List<int>>? stdinSub;

  Future<void> closeServer() async {
    if (closing) {
      return;
    }
    closing = true;

    onShutdown?.call();

    if (server != null) {
      await server.close();
    }

    await stdinSub?.cancel();

    if (tempDir != null) {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    }
  }

  void armForceExit() {
    forceExitTimer ??= Timer(const Duration(seconds: 2), () {
      exit(0);
    });
  }

  final waits = <Future<void>>[];

  if (listenToSignals) {
    waits.add(ProcessSignal.sigint.watch().first.then((_) {}));
    if (!Platform.isWindows) {
      waits.add(ProcessSignal.sigterm.watch().first.then((_) {}));
    }
  }

  if (shutdownFuture != null) {
    waits.add(shutdownFuture);
  }

  if (listenToStdin && !Platform.isWindows) {
    final ctrlC = Completer<void>();
    try {
      stdin.lineMode = false;
      stdin.echoMode = false;
      stdinSub = stdin.listen((data) {
        if (data.contains(3) && !ctrlC.isCompleted) {
          ctrlC.complete();
        }
      });
      waits.add(ctrlC.future);
    } catch (_) {
      // Ignore stdin configuration errors on unsupported terminals.
    }
  }

  if (waits.isEmpty) {
    armForceExit();
    await closeServer();
    forceExitTimer?.cancel();
    return;
  }

  await Future.any(waits);

  armForceExit();
  await closeServer();
  forceExitTimer?.cancel();
}

Future<_HttpsCredentials> _resolveHttpsCredentials({
  required String? certFile,
  required String? keyFile,
  required Directory? tempDir,
}) async {
  if (certFile != null && certFile.isNotEmpty && keyFile != null && keyFile.isNotEmpty) {
    return _HttpsCredentials(certFile, keyFile, tempDir);
  }

  final workDir = tempDir ?? await Directory.systemTemp.createTemp('openssl_web_');
  final openSsl = OpenSSL();
  final key = openSsl.generateRsa(2048);
  final builder = openSsl.newCertificateBuilder();
  builder.setSubject(commonName: 'OpenSSL Web Server');
  builder.setIssuerAsSubject();
  builder.setPublicKey(key);
  builder.setValidity(notAfterOffset: 86400);
  final cert = builder.sign(key);

  final certPath = '${workDir.path}/cert.pem';
  final keyPath = '${workDir.path}/key.pem';
  await File(certPath).writeAsString(cert.toPem());
  await File(keyPath).writeAsString(key.toPrivateKeyPem());

  return _HttpsCredentials(certPath, keyPath, workDir);
}

class _HttpsCredentials {
  final String certPath;
  final String keyPath;
  final Directory? tempDir;

  _HttpsCredentials(this.certPath, this.keyPath, this.tempDir);
}

String _nextArg(List<String> args, int index, String flag) {
  if (index >= args.length) {
    throw ArgumentError('Missing value for $flag');
  }
  return args[index];
}
