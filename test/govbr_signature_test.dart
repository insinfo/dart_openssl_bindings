import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/cms/cms_pkcs7_signer.dart';
import 'package:openssl_bindings/src/crypto/evp_pkey.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';
import 'package:test/test.dart';

class FakeGovBrServer {
  FakeGovBrServer(this._openSsl);

  final OpenSSL _openSsl;
  late final EvpPkey _privateKey;
  late final String _certPem;
  late final Uint8List _certDer;
  late final HttpServer _server;
  late final Uri baseUri;

  static const String _tokenValue = 'fake-token';

  Future<void> start() async {
    _privateKey = _openSsl.generateRsa(2048);

    final builder = X509CertificateBuilder(_openSsl)
      ..setSubject(
        commonName: 'GovBR Fake Signer',
        organization: 'GovBR',
        country: 'BR',
      )
      ..setIssuerAsSubject()
      ..setValidity(notAfterOffset: 3600)
      ..setPublicKey(_privateKey);

    final cert = builder.sign(_privateKey);
    _certPem = cert.toPem();
    _certDer = _pemToDer(_certPem);

    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    baseUri = Uri.parse('http://${_server.address.host}:${_server.port}');

    unawaited(_server.forEach(_handleRequest));
  }

  Future<void> close() async {
    await _server.close(force: true);
  }

  Future<void> _handleRequest(HttpRequest request) async {
    try {
      final path = request.uri.path;

      if (request.method == 'POST' &&
          (path == '/oauth2.0/token' || path == '/oauth/token')) {
        _writeJson(request.response, 200, {
          'access_token': _tokenValue,
          'token_type': 'Bearer',
          'expires_in': 600,
        });
        return;
      }

      if (request.method == 'GET' && path == '/externo/v2/certificadoPublico') {
        if (!_hasValidBearer(request)) {
          _writeJson(request.response, 401, {
            'error': 'unauthorized',
            'message': 'Bearer token ausente/inválido'
          });
          return;
        }
        request.response
          ..statusCode = 200
          ..headers.contentType = ContentType('application', 'x-pem-file')
          ..write(_certPem);
        await request.response.close();
        return;
      }

      if (request.method == 'POST' && path == '/externo/v2/assinarPKCS7') {
        if (!_hasValidBearer(request)) {
          _writeJson(request.response, 401, {
            'error': 'unauthorized',
            'message': 'Bearer token ausente/inválido'
          });
          return;
        }

        final body = await utf8.decoder.bind(request).join();
        final decoded = jsonDecode(body) as Map<String, dynamic>;
        final hashBase64 = decoded['hashBase64']?.toString();

        if (hashBase64 == null || hashBase64.isEmpty) {
          _writeJson(request.response, 400, {
            'error': 'invalid_request',
            'message': 'hashBase64 é obrigatório'
          });
          return;
        }

        Uint8List hashBytes;
        try {
          hashBytes = Uint8List.fromList(base64Decode(hashBase64));
        } catch (_) {
          _writeJson(request.response, 400, {
            'error': 'invalid_request',
            'message': 'hashBase64 inválido'
          });
          return;
        }

        final signer = CmsPkcs7Signer(_openSsl);
        final pkcs7 = signer.signDetachedDigest(
          contentDigest: hashBytes,
          certificateDer: _certDer,
          privateKey: _privateKey,
        );

        request.response
          ..statusCode = 200
          ..headers.contentType =
              ContentType('application', 'pkcs7-signature')
          ..add(pkcs7);
        await request.response.close();
        return;
      }

      request.response
        ..statusCode = 404
        ..write('not found');
      await request.response.close();
    } catch (e) {
      request.response
        ..statusCode = 500
        ..write('error: $e');
      await request.response.close();
    }
  }

  bool _hasValidBearer(HttpRequest request) {
    final auth = request.headers.value(HttpHeaders.authorizationHeader);
    if (auth == null) return false;
    final parts = auth.split(' ');
    if (parts.length != 2) return false;
    if (parts.first.toLowerCase() != 'bearer') return false;
    return parts[1] == _tokenValue;
  }

  void _writeJson(HttpResponse res, int status, Map<String, dynamic> body) {
    res
      ..statusCode = status
      ..headers.contentType = ContentType('application', 'json')
      ..write(jsonEncode(body));
    res.close();
  }
}

void main() {
  group('Fake GovBR assinatura + cliente (hash)', () {
    late OpenSSL openSsl;
    late FakeGovBrServer server;
    late HttpClient client;

    setUpAll(() async {
      openSsl = OpenSSL();
      server = FakeGovBrServer(openSsl);
      await server.start();
      client = HttpClient();
    });

    tearDownAll(() async {
      client.close(force: true);
      await server.close();
    });

    test('Client obtains token and signs hash', () async {
      final token = await _fetchToken(client, server.baseUri);
      final certPem = await _fetchCert(client, server.baseUri, token);
      expect(certPem, contains('BEGIN CERTIFICATE'));

      final content = 'conteudo-para-assinar'.codeUnits;
      final digest = openSsl.sha256(content);

      final signature =
          await _signHash(client, server.baseUri, token, digest);

      expect(signature, isNotEmpty);
      expect(signature.first, equals(0x30)); // ASN.1 SEQUENCE

      final verified = openSsl.verifyCmsDetached(
        cmsDer: signature,
        content: Uint8List.fromList(content),
        trustedCertDer: _pemToDer(certPem),
      );
      expect(verified, isTrue);
    });
  });
}

Future<String> _fetchToken(HttpClient client, Uri baseUri) async {
  final uri = baseUri.resolve('/oauth2.0/token');
  final req = await client.postUrl(uri);
  req.headers.contentType =
      ContentType('application', 'x-www-form-urlencoded');
  req.write('grant_type=authorization_code&code=fake');
  final res = await req.close();
  final body = await utf8.decoder.bind(res).join();
  final json = jsonDecode(body) as Map<String, dynamic>;
  return json['access_token'] as String;
}

Future<String> _fetchCert(HttpClient client, Uri baseUri, String token) async {
  final uri = baseUri.resolve('/externo/v2/certificadoPublico');
  final req = await client.getUrl(uri);
  req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
  final res = await req.close();
  return await utf8.decoder.bind(res).join();
}

Future<Uint8List> _signHash(
    HttpClient client, Uri baseUri, String token, Uint8List digest) async {
  final uri = baseUri.resolve('/externo/v2/assinarPKCS7');
  final req = await client.postUrl(uri);
  req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
  req.headers.contentType = ContentType('application', 'json');
  req.write(jsonEncode({'hashBase64': base64Encode(digest)}));
  final res = await req.close();
  final bytes = await _readResponseBytes(res);
  return Uint8List.fromList(bytes);
}

Future<List<int>> _readResponseBytes(HttpClientResponse res) async {
  final chunks = <int>[];
  await for (final chunk in res) {
    chunks.addAll(chunk);
  }
  return chunks;
}

Uint8List _pemToDer(String pem) {
  final lines = pem
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty && !l.startsWith('-----'))
      .join('');
  return Uint8List.fromList(base64Decode(lines));
}
