import 'dart:io';

import 'package:test/test.dart';

/// OpenSSL providers live in the **process**-wide default context, and
/// `dart test` runs every suite in the same process (one isolate per file).
/// If another suite loaded `legacy`, the `PKCS12_parse` in this scenario would
/// start working. That is why the scenario runs in a separate process.
void main() {
  test(
    'PKCS12_parse without the legacy provider blames the algorithm, not the password',
    () {
      final result = Process.runSync(
        Platform.resolvedExecutable,
        [
          'run',
          'test/support/parse_legacy_p12_without_provider.dart',
          'test/fixtures/legacy_rc2_40.p12',
          'senha123',
        ],
        stdoutEncoding: systemEncoding,
        stderrEncoding: systemEncoding,
      );

      final output = '${result.stdout}${result.stderr}';
      expect(result.exitCode, 0, reason: output);
      expect(output, contains('pbeWithSHA1And40BitRC2-CBC'));
      expect(output, contains('legacy'));
      expect(output, contains('NOT a wrong password'));
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
