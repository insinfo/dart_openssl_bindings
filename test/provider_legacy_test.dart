import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

/// PKCS#12 encrypted with pbeWithSHA1And40BitRC2-CBC (40-bit RC2), produced by
/// `openssl pkcs12 -export -legacy -certpbe PBE-SHA1-RC2-40 -keypbe
/// PBE-SHA1-RC2-40 -macalg sha1`. It exercises the `legacy` provider, which
/// OpenSSL 3.x does not load on its own.
final File _p12Legado = File('test/fixtures/legacy_rc2_40.p12');
const String _senhaP12 = 'senha123';

void main() {
  group('OpenSSL 3.x providers', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('the default provider is available', () {
      expect(openSsl.isProviderAvailable(kDefaultProvider), isTrue);
    });

    test('loading a missing provider fails with a clear message', () {
      expect(
        () => openSsl.loadProvider('provider-que-nao-existe'),
        throwsA(
          isA<OpenSslException>().having(
            (e) => e.message,
            'message',
            contains('provider-que-nao-existe'),
          ),
        ),
      );
    });

    test('loading a missing provider returns null when optional', () {
      expect(
        openSsl.loadProvider('provider-que-nao-existe', required: false),
        isNull,
      );
    });

    test('loading the legacy provider is idempotent', () {
      final provider = openSsl.loadLegacyProvider(required: false);
      if (provider == null) {
        markTestSkipped('legacy module not found on this machine');
        return;
      }

      expect(provider.name, kLegacyProvider);
      expect(provider.handle, isNot(nullptr));
      expect(identical(openSsl.loadLegacyProvider(), provider), isTrue);
      expect(openSsl.loadedProviders.keys, contains(kLegacyProvider));
    });

    test('the default provider stays active after loading legacy', () {
      if (openSsl.loadLegacyProvider(required: false) == null) {
        markTestSkipped('legacy module not found on this machine');
        return;
      }

      // Without retain_fallbacks OpenSSL would disable the default provider
      // and this would stop working.
      final hash = openSsl.sha256('abc'.codeUnits);
      expect(
        hash
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
      expect(() => openSsl.generateRsa(2048), returnsNormally);
    });
  });

  group('PKCS#12 with legacy algorithms', () {
    late OpenSSL openSsl;
    late Uint8List der;

    setUp(() {
      openSsl = OpenSSL();
      der = _p12Legado.readAsBytesSync();
    });

    test('detects the legacy algorithm without opening the file', () {
      expect(
        openSsl.pkcs12LegacyAlgorithms(der),
        contains('pbeWithSHA1And40BitRC2-CBC'),
      );
      expect(openSsl.pkcs12NeedsLegacyProvider(der), isTrue);
    });

    test('parsePkcs12(legacy: true) abre o arquivo', () {
      if (openSsl.loadLegacyProvider(required: false) == null) {
        markTestSkipped('legacy module not found on this machine');
        return;
      }

      final bundle = openSsl.parsePkcs12(
        der,
        password: _senhaP12,
        legacy: true,
      );

      expect(bundle.certificate.subject, contains('Legacy P12 Fixture'));
      expect(bundle.privateKey.handle, isNot(nullptr));
    });

    test('legacy: true é alias de legacy: true', () {
      if (openSsl.loadLegacyProvider(required: false) == null) {
        markTestSkipped('legacy module not found on this machine');
        return;
      }

      final bundle = openSsl.parsePkcs12(
        der,
        password: _senhaP12,
        legacy: true,
      );
      expect(bundle.certificate.subject, contains('Legacy P12 Fixture'));
    });

    test('a wrong password is still reported as such once legacy is loaded',
        () {
      if (openSsl.loadLegacyProvider(required: false) == null) {
        markTestSkipped('legacy module not found on this machine');
        return;
      }

      expect(
        () => openSsl.parsePkcs12(der, password: 'errada', legacy: true),
        throwsA(
          isA<OpenSslException>().having(
            (e) => e.message,
            'message',
            contains('wrong password'),
          ),
        ),
      );
    });

    test('a modern PKCS#12 is not flagged as legacy', () {
      final key = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'P12 Moderno')
        ..setIssuerAsSubject()
        ..setPublicKey(key)
        ..setValidity(notAfterOffset: 3600);
      final cert = builder.sign(key);

      final moderno = openSsl.createPkcs12(
        privateKey: key,
        certificate: cert,
        password: _senhaP12,
      );

      expect(openSsl.pkcs12LegacyAlgorithms(moderno), isEmpty);
      expect(openSsl.pkcs12NeedsLegacyProvider(moderno), isFalse);

      final bundle = openSsl.parsePkcs12(moderno, password: _senhaP12);
      expect(bundle.certificate.subject, contains('P12 Moderno'));
    });
  });
}
