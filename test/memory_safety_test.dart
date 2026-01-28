import 'dart:io';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Memory safety regression', () {
    late OpenSSL openSsl;

    setUpAll(() {
      openSsl = OpenSSL();
    });

    test('Repeated ASN1_TIME_to_tm parsing', () {
      final key = openSsl.generateRsa(2048);
      try {
        const rounds = 5;
        const warmupRounds = 1;
        const iterationsPerRound = 200;
        final maxAllowedDeltaMb = double.tryParse(
              Platform.environment['MEMORY_SAFETY_MAX_MB'] ?? '',
            ) ??
            100.0;

        final rssBefore = ProcessInfo.currentRss;
        print('RSS before: ${_formatBytes(rssBefore)}');

        int? firstRoundRss;
        int? lastRoundRss;

        for (var round = 1; round <= rounds; round++) {
          for (var i = 0; i < iterationsPerRound; i++) {
            final builder = X509CertificateBuilder(openSsl);
            builder.setSubject(commonName: 'Test $round-$i');
            builder.setIssuerAsSubject();
            builder.setPublicKey(key);
            builder.setValidity(notBeforeOffset: 0, notAfterOffset: 3600);
            final cert = builder.sign(key);
            expect(cert.notBefore, isNotNull);
            expect(cert.notAfter, isNotNull);
            cert.dispose();
          }

          sleep(const Duration(milliseconds: 20));

          final rssRound = ProcessInfo.currentRss;
          if (round > warmupRounds) {
            firstRoundRss ??= rssRound;
            lastRoundRss = rssRound;
          }
          print('RSS after round $round: ${_formatBytes(rssRound)}');
        }

        final rssAfter = ProcessInfo.currentRss;
        print('RSS after:  ${_formatBytes(rssAfter)}');
        final delta = rssAfter - rssBefore;
        print('RSS delta:  ${_formatBytes(delta)}');

        final roundDeltaBytes = (lastRoundRss ?? rssAfter) - (firstRoundRss ?? rssBefore);
        final roundDeltaMb = roundDeltaBytes / (1024 * 1024);
        final measuredStart = warmupRounds + 1;
        print('RSS delta (round $measuredStart -> round $rounds): ${roundDeltaMb.toStringAsFixed(2)} MB');
        print('RSS limit: ${maxAllowedDeltaMb.toStringAsFixed(2)} MB');
        expect(roundDeltaMb, lessThan(maxAllowedDeltaMb));
      } finally {
        key.dispose();
      }
    });
  });
}

String _formatBytes(int bytes) {
  const mb = 1024 * 1024;
  return '${(bytes / mb).toStringAsFixed(2)} MB';
}
