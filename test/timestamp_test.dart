import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

/// A minimal internal TSA: a root CA and a signing certificate carrying
/// `extendedKeyUsage = critical, timeStamping`, which is what OpenSSL demands
/// from a time-stamp signer.
class _Tsa {
  final OpenSSL openSsl;

  late final EvpPkey rootKey;
  late final X509Certificate root;
  late final EvpPkey signerKey;
  late final X509Certificate signer;

  _Tsa(this.openSsl, {bool withTimeStampingEku = true}) {
    rootKey = openSsl.generateRsa(2048);
    root = (X509CertificateBuilder(openSsl)
          ..setSubject(commonName: 'AC Raiz Interna', organization: 'Teste')
          ..setIssuerAsSubject()
          ..setPublicKey(rootKey)
          ..setValidity(notAfterOffset: 86400)
          ..addBasicConstraints(isCa: true, critical: true))
        .sign(rootKey);

    signerKey = openSsl.generateRsa(2048);
    final builder = X509CertificateBuilder(openSsl)
      ..setSubject(commonName: 'Carimbo do Tempo Interno')
      ..setIssuer(issuerCert: root)
      ..setPublicKey(signerKey)
      ..setValidity(notAfterOffset: 86400);
    if (withTimeStampingEku) {
      builder.addExtendedKeyUsage(['timeStamping'], critical: true);
    }
    signer = builder.sign(rootKey);
  }

  Uint8List stamp(
    Uint8List requestDer, {
    BigInt? serialNumber,
    TimestampAccuracy? accuracy,
    String policyOid = '1.3.6.1.4.1.99999.1.1',
  }) =>
      openSsl.createTimestampResponse(
        requestDer: requestDer,
        signerCertificate: signer,
        signerKey: signerKey,
        defaultPolicyOid: policyOid,
        serialNumber: serialNumber,
        accuracy: accuracy,
      );
}

void main() {
  late OpenSSL openSsl;
  late _Tsa tsa;
  late Uint8List documentHash;

  setUp(() {
    openSsl = OpenSSL();
    tsa = _Tsa(openSsl);
    documentHash = openSsl.sha256('the signature bytes'.codeUnits);
  });

  group('buildTimestampRequest', () {
    test('produces a DER request with a nonce by default', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);

      expect(request.der, isNotEmpty);
      expect(request.hashAlgorithm, 'SHA256');
      expect(request.hash, documentHash);
      expect(request.nonce, isNotNull);
      expect(request.requestCertificate, isTrue);
    });

    test('two requests carry different nonces', () {
      final a = openSsl.buildTimestampRequest(hash: documentHash);
      final b = openSsl.buildTimestampRequest(hash: documentHash);
      expect(a.nonce, isNot(b.nonce));
    });

    test('the nonce can be turned off', () {
      final request =
          openSsl.buildTimestampRequest(hash: documentHash, useNonce: false);
      expect(request.nonce, isNull);
    });

    test('rejects a hash whose length does not match the algorithm', () {
      expect(
        () => openSsl.buildTimestampRequest(
          hash: Uint8List(20),
          hashAlgorithm: 'SHA256',
        ),
        throwsArgumentError,
      );
    });

    test('rejects an unknown digest and an invalid policy OID', () {
      expect(
        () => openSsl.buildTimestampRequest(
          hash: documentHash,
          hashAlgorithm: 'NOPE',
        ),
        throwsArgumentError,
      );
      expect(
        () => openSsl.buildTimestampRequest(
          hash: documentHash,
          policyOid: 'not-an-oid',
        ),
        throwsArgumentError,
      );
    });

    test('hashes the data itself when asked to', () {
      final data = Uint8List.fromList('a document'.codeUnits);
      final request = openSsl.buildTimestampRequestForData(data);
      expect(request.hash, openSsl.sha256(data));
    });
  });

  group('createTimestampResponse', () {
    test('issues a granted token carrying the request imprint', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(
        request.der,
        serialNumber: BigInt.from(42),
      );

      final response = openSsl.parseTimestampResponse(responseDer);
      expect(response.status, TimestampStatus.granted);
      expect(response.isGranted, isTrue);
      expect(response.failureInfo, isNull);

      final token = response.token!;
      expect(token.messageImprint, documentHash);
      expect(token.hashAlgorithm, 'SHA256');
      expect(token.serialNumber, BigInt.from(42));
      expect(token.nonce, request.nonce);
      expect(token.policyOid, '1.3.6.1.4.1.99999.1.1');
      expect(token.version, 1);
      expect(
        token.genTime.difference(DateTime.now().toUtc()).abs(),
        lessThan(const Duration(minutes: 5)),
      );
    });

    test('the accuracy declared by the TSA lands in the token', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(
        request.der,
        accuracy: const TimestampAccuracy(seconds: 1, millis: 500),
      );

      final token = openSsl.parseTimestampResponse(responseDer).token!;
      expect(token.accuracy, isNotNull);
      expect(token.accuracy!.seconds, 1);
      expect(token.accuracy!.millis, 500);
      expect(token.accuracy!.asDuration, const Duration(milliseconds: 1500));
    });

    test('rejects a digest the TSA does not accept', () {
      final request = openSsl.buildTimestampRequest(
        hash: openSsl.digest('SHA1', Uint8List.fromList('data'.codeUnits)),
        hashAlgorithm: 'SHA1',
      );

      // The TSA only accepts SHA-2 by default.
      final response = openSsl.parseTimestampResponse(tsa.stamp(request.der));
      expect(response.status, TimestampStatus.rejection);
      expect(response.isGranted, isFalse);
      expect(response.token, isNull);
      expect(response.failureInfo, isNotNull);
      expect(response.statusText, isNotNull);
    });

    test('refuses to sign without the timeStamping extended key usage', () {
      final wrongTsa = _Tsa(openSsl, withTimeStampingEku: false);
      final request = openSsl.buildTimestampRequest(hash: documentHash);

      expect(
        () => wrongTsa.stamp(request.der),
        throwsA(
          isA<OpenSslException>().having(
            (e) => e.message,
            'message',
            contains('timeStamping'),
          ),
        ),
      );
    });

    test('the serial number comes from the caller, token after token', () {
      final serials = [BigInt.from(7), BigInt.from(8), BigInt.two.pow(70)];
      for (final serial in serials) {
        final request = openSsl.buildTimestampRequest(hash: documentHash);
        final token = openSsl
            .parseTimestampResponse(
              tsa.stamp(request.der, serialNumber: serial),
            )
            .token!;
        expect(token.serialNumber, serial);
      }
    });
  });

  group('verifyTimestamp', () {
    test('accepts a token issued by the trusted TSA', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(request.der, serialNumber: BigInt.one);

      final check = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: documentHash,
        nonce: request.nonce,
        anchors: [tsa.root],
      );

      expect(check.valid, isTrue, reason: check.error);
      expect(check.token!.messageImprint, documentHash);
    });

    test('rejects a token for a different hash', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(request.der);

      final check = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: openSsl.sha256('another document'.codeUnits),
        nonce: request.nonce,
        anchors: [tsa.root],
      );

      expect(check.valid, isFalse);
      expect(check.error, isNotEmpty);
    });

    test('rejects a replayed token when the nonce does not match', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(request.der);

      // The same token presented against a fresh request: this is exactly the
      // replay the nonce is there to catch.
      final other = openSsl.buildTimestampRequest(hash: documentHash);
      final check = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: documentHash,
        nonce: other.nonce,
        anchors: [tsa.root],
      );

      expect(check.valid, isFalse);
      expect(check.error, isNotEmpty);
    });

    test('rejects a token from an untrusted TSA', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(request.der);

      final stranger = _Tsa(openSsl);
      final check = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: documentHash,
        nonce: request.nonce,
        anchors: [stranger.root],
      );

      expect(check.valid, isFalse);
      expect(check.error, isNotEmpty);
    });

    test('verifies a bare archived token, with no request left', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final token =
          openSsl.parseTimestampResponse(tsa.stamp(request.der)).token!;

      // Only the token was archived: no nonce to compare, everything else is
      // still checked.
      final check = openSsl.verifyTimestamp(
        tokenDer: token.der,
        hash: documentHash,
        anchors: [tsa.root],
      );

      expect(check.valid, isTrue, reason: check.error);
      expect(check.token!.serialNumber, token.serialNumber);
    });

    test('a bare token still fails against the wrong hash', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final token =
          openSsl.parseTimestampResponse(tsa.stamp(request.der)).token!;

      final check = openSsl.verifyTimestamp(
        tokenDer: token.der,
        hash: openSsl.sha256('tampered'.codeUnits),
        anchors: [tsa.root],
      );

      expect(check.valid, isFalse);
    });

    test('checks the policy when one is required', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final responseDer = tsa.stamp(request.der);

      final matching = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: documentHash,
        nonce: request.nonce,
        policyOid: '1.3.6.1.4.1.99999.1.1',
        anchors: [tsa.root],
      );
      expect(matching.valid, isTrue, reason: matching.error);

      final different = openSsl.verifyTimestamp(
        responseDer: responseDer,
        hash: documentHash,
        nonce: request.nonce,
        policyOid: '1.3.6.1.4.1.99999.9.9',
        anchors: [tsa.root],
      );
      expect(different.valid, isFalse);
    });

    test('demands exactly one of responseDer and tokenDer, and an anchor', () {
      expect(
        () => openSsl.verifyTimestamp(hash: documentHash, anchors: [tsa.root]),
        throwsArgumentError,
      );
      expect(
        () => openSsl.verifyTimestamp(
          responseDer: Uint8List(0),
          tokenDer: Uint8List(0),
          hash: documentHash,
          anchors: [tsa.root],
        ),
        throwsArgumentError,
      );
      expect(
        () => openSsl.verifyTimestamp(
          tokenDer: Uint8List(1),
          hash: documentHash,
          anchors: [],
        ),
        throwsArgumentError,
      );
    });
  });

  group('parseTimestampToken', () {
    test('reads a bare token', () {
      final request = openSsl.buildTimestampRequest(hash: documentHash);
      final fromResponse =
          openSsl.parseTimestampResponse(tsa.stamp(request.der)).token!;

      final token = openSsl.parseTimestampToken(fromResponse.der);
      expect(token.messageImprint, documentHash);
      expect(token.genTime, fromResponse.genTime);
      expect(token.nonce, request.nonce);
    });

    test('rejects something that is not a time-stamp token', () {
      expect(
        () => openSsl.parseTimestampToken(Uint8List.fromList([0x30, 0x03])),
        throwsA(isA<OpenSslException>()),
      );
    });
  });
}
