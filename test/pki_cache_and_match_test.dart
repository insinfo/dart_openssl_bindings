import 'dart:async';
import 'dart:typed_data';

import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

import 'certs.dart';

void main() {
  group('Issuer matching and caches', () {
    late OpenSSL openssl;
    late Uint8List certDer;

    setUp(() {
      openssl = OpenSSL();
      certDer = Uint8List.fromList(rawDerCertificate);
    });

    test('fingerprint helper is deterministic', () {
      final fp1 = openssl.fingerprintSha256(certDer);
      final fp2 = openssl.fingerprintSha256(certDer);

      expect(fp1, equals(fp2));
      expect(fp1.length, equals(64));
    });

    test('certificate parse cache reuses pointer identity', () {
      final p1 = openssl.getOrCreateParsedX509(certDer);
      final p2 = openssl.getOrCreateParsedX509(certDer);

      try {
        expect(p1.address, equals(p2.address));
      } finally {
        openssl.bindings.X509_free(p1);
        openssl.bindings.X509_free(p2);
      }
    });

    test('store cache reuses X509_STORE by key', () {
      final key = openssl.fingerprintSha256(certDer);
      final s1 = openssl.getOrCreateStore(key, [certDer]);
      final s2 = openssl.getOrCreateStore(key, [certDer]);

      expect(identical(s1, s2), isTrue);
    });

    test('extractAkiSki and certMatchesIssuer work with binary IDs', () {
      final certPtr = openssl.getOrCreateParsedX509(certDer);
      try {
        final data = openssl.extractAkiSki(certPtr);
        final serial = openssl.x509GetSerialBytes(certPtr);

        expect(data.serialBytes, equals(serial));
        expect(data.issuerNameHash, isNotEmpty);

        final positive = openssl.certMatchesIssuer(
          childAki: data.ski,
          issuerSki: data.ski,
          issuerSerialBytes: data.serialBytes,
          issuerNameHash: data.issuerNameHash,
        );

        final negative = openssl.certMatchesIssuer(
          childAki: Uint8List.fromList(const [1, 2, 3]),
          issuerSki: Uint8List.fromList(const [4, 5, 6]),
          issuerSerialBytes: data.serialBytes,
          issuerNameHash: data.issuerNameHash,
        );

        expect(positive, isTrue);
        expect(negative, isFalse);
      } finally {
        openssl.bindings.X509_free(certPtr);
      }
    });

    test('prefilter falls back on ambiguity/failure', () {
      final all = [1, 2, 3, 4];

      final noMatch = openssl.prefilterIssuerCandidates<int>(
        candidates: all,
        matches: (n) => n > 10,
      );
      final ambiguous = openssl.prefilterIssuerCandidates<int>(
        candidates: all,
        matches: (n) => n.isEven,
      );
      final unique = openssl.prefilterIssuerCandidates<int>(
        candidates: all,
        matches: (n) => n == 3,
      );

      expect(noMatch, equals(all));
      expect(ambiguous, equals(all));
      expect(unique, equals([3]));
    });

    test('prefilter returns original list when candidate set has one item', () {
      final single = [42];
      final result = openssl.prefilterIssuerCandidates<int>(
        candidates: single,
        matches: (_) => false,
      );

      expect(identical(result, single), isTrue);
      expect(result, equals(single));
    });

    test('certMatchesIssuer rejects empty binary/text hints', () {
      expect(
        openssl.certMatchesIssuer(childAki: Uint8List(0)),
        isFalse,
      );
      expect(
        openssl.certMatchesIssuer(issuerSki: Uint8List(0)),
        isFalse,
      );
      expect(
        openssl.certMatchesIssuer(issuerSerialBytes: Uint8List(0)),
        isFalse,
      );
      expect(
        openssl.certMatchesIssuer(issuerNameHash: '   '),
        isFalse,
      );
    });

    test('issuerSerialKey normalizes issuer hash to lowercase', () {
      final key = openssl.issuerSerialKey(
        issuerNameHash: 'ABCD1234',
        issuerSerialBytes: Uint8List.fromList(const [0x0A, 0x0B]),
      );

      expect(key, equals('abcd1234:0a0b'));
    });

    test('CRL cache returns copy and expires by TTL', () async {
      const cacheKey = 'issuerA|urlA';
      final original = Uint8List.fromList(const [1, 2, 3]);

      openssl.putCachedCrl(
        cacheKey,
        original,
        ttl: const Duration(milliseconds: 10),
      );

      final firstRead = openssl.getCachedCrl(cacheKey);
      expect(firstRead, equals(original));
      expect(identical(firstRead, original), isFalse);

      firstRead![0] = 99;
      final secondRead = openssl.getCachedCrl(cacheKey);
      expect(secondRead, equals(Uint8List.fromList(const [1, 2, 3])));

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(openssl.getCachedCrl(cacheKey), isNull);
    });

    test('OCSP cache returns null for misses and respects TTL', () async {
      const cacheKey = 'issuerB|urlB';
      expect(openssl.getCachedOcsp(cacheKey), isNull);

      openssl.putCachedOcsp(
        cacheKey,
        Uint8List.fromList(const [9, 8, 7]),
        ttl: const Duration(milliseconds: 10),
      );

      expect(openssl.getCachedOcsp(cacheKey), isNotNull);
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(openssl.getCachedOcsp(cacheKey), isNull);
    });
  });
}
