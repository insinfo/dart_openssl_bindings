import 'dart:io';

import 'package:openssl_bindings/openssl.dart';

/// Helper for `test/pkcs12_legacy_message_test.dart`.
///
/// It runs in a separate process because OpenSSL providers are loaded into the
/// process-wide default context: if another test file loaded `legacy`, the
/// `PKCS12_parse` here would start working and the test would lose its point.
/// `dart test` runs each suite in an isolate, but all in the same process.
void main(List<String> args) {
  final openSsl = OpenSSL();
  final der = File(args[0]).readAsBytesSync();

  if (openSsl.loadedProviders.isNotEmpty) {
    stdout.writeln('ERROR: a provider was loaded too early');
    exit(2);
  }

  try {
    openSsl.parsePkcs12(der, password: args[1]);
    stdout.writeln('OPENED');
    exit(3);
  } on OpenSslException catch (e) {
    stdout.writeln(e.message);
  }
}
