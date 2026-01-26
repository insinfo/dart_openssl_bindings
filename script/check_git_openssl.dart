import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';

void main() {
  final locations = _candidateGitDirs();
  final pair = _findGitOpenSslDlls(locations);

  if (pair == null) {
    print('Git OpenSSL DLLs not found in:');
    for (final dir in locations) {
      print('  - $dir');
    }
    exitCode = 1;
    return;
  }

  final (sslPath, cryptoPath) = pair;
  print('Using Git OpenSSL DLLs:');
  print('  libssl: $sslPath');
  print('  libcrypto: $cryptoPath');

  try {
    final openssl = OpenSSL(sslPath: sslPath, cryptoPath: cryptoPath);

    final digest = openssl.digest('sha256', Uint8List.fromList('ok'.codeUnits));
    final key = openssl.generateRsa(2048);
    final keyPem = key.toPrivateKeyPem();

    // Exercise critical X509 ASN1_TIME_to_tm path repeatedly.
    final cert = X509CertificateBuilder(openssl)
      ..setSubject(commonName: 'Git OpenSSL Test')
      ..setIssuerAsSubject()
      ..setValidity(notBeforeOffset: 0, notAfterOffset: 86400)
      ..setPublicKey(key);
    final x509 = cert.sign(key);

    final before = x509.notBefore;
    final after = x509.notAfter;
    if (before == null || after == null) {
      throw StateError('Failed to parse ASN1_TIME from certificate');
    }

    for (var i = 0; i < 5000; i++) {
      final nb = x509.notBefore;
      final na = x509.notAfter;
      if (nb == null || na == null) {
        throw StateError('ASN1_TIME parsing failed at iteration $i');
      }
    }

    print('OpenSSL OK.');
    print('OpenSSL version: ${openssl.opensslVersionString}');
    print('SHA-256 digest length: ${digest.length}');
    print('RSA private key PEM length: ${keyPem.length}');
    print('ASN1_TIME parsing OK: ${before.toIso8601String()} -> ${after.toIso8601String()}');
  } catch (e, s) {
    print('Failed to initialize OpenSSL from Git DLLs: $e');
    print(s);
    exitCode = 2;
  }
}

List<String> _candidateGitDirs() {
  final programFiles = Platform.environment['ProgramFiles'] ?? r'C:\Program Files';
  final programFilesX86 = Platform.environment['ProgramFiles(x86)'];

  final candidates = <String>{
    '$programFiles\\Git\\mingw64\\bin',
    '$programFiles\\Git\\usr\\bin',
    '$programFiles\\Git\\libexec\\git-core',
  };

  if (programFilesX86 != null && programFilesX86.isNotEmpty) {
    candidates.add('$programFilesX86\\Git\\mingw64\\bin');
    candidates.add('$programFilesX86\\Git\\usr\\bin');
    candidates.add('$programFilesX86\\Git\\libexec\\git-core');
  }

  return candidates.toList();
}

(String sslPath, String cryptoPath)? _findGitOpenSslDlls(List<String> dirs) {
  for (final dir in dirs) {
    final directory = Directory(dir);
    if (!directory.existsSync()) {
      continue;
    }

    final ssl = directory
        .listSync()
        .whereType<File>()
        .map((f) => f.path)
        .firstWhere(
          (p) => _fileNameMatches(p, 'libssl'),
          orElse: () => '',
        );

    final crypto = directory
        .listSync()
        .whereType<File>()
        .map((f) => f.path)
        .firstWhere(
          (p) => _fileNameMatches(p, 'libcrypto'),
          orElse: () => '',
        );

    if (ssl.isNotEmpty && crypto.isNotEmpty) {
      return (ssl, crypto);
    }
  }
  return null;
}

bool _fileNameMatches(String path, String prefix) {
  final lower = path.toLowerCase();
  return lower.contains('\\$prefix') && lower.endsWith('.dll');
}
