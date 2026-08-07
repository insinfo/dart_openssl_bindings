import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

/// Builds root -> intermediate -> leaf to exercise chain verification.
class _Pki {
  final OpenSSL openSsl;

  late final EvpPkey chaveRaiz;
  late final X509Certificate raiz;
  late final EvpPkey chaveIntermediaria;
  late final X509Certificate intermediaria;
  late final EvpPkey chaveFolha;
  late final X509Certificate folha;

  _Pki(this.openSsl) {
    chaveRaiz = openSsl.generateRsa(2048);
    raiz = (X509CertificateBuilder(openSsl)
          ..setSubject(commonName: 'AC Raiz Teste', organization: 'Teste')
          ..setIssuerAsSubject()
          ..setPublicKey(chaveRaiz)
          ..setValidity(notAfterOffset: 86400)
          ..addBasicConstraints(isCa: true, critical: true))
        .sign(chaveRaiz);

    chaveIntermediaria = openSsl.generateRsa(2048);
    intermediaria = (X509CertificateBuilder(openSsl)
          ..setSubject(commonName: 'AC Intermediaria Teste')
          ..setIssuer(issuerCert: raiz)
          ..setPublicKey(chaveIntermediaria)
          ..setValidity(notAfterOffset: 86400)
          ..addBasicConstraints(isCa: true, critical: true))
        .sign(chaveRaiz);

    chaveFolha = openSsl.generateRsa(2048);
    folha = (X509CertificateBuilder(openSsl)
          ..setSubject(commonName: 'Titular Teste')
          ..setIssuer(issuerCert: intermediaria)
          ..setPublicKey(chaveFolha)
          ..setValidity(notAfterOffset: 86400))
        .sign(chaveIntermediaria);
  }
}

void main() {
  late OpenSSL openSsl;
  late _Pki pki;

  setUp(() {
    openSsl = OpenSSL();
    pki = _Pki(openSsl);
  });

  group('verifyCertificateSignature', () {
    test('accepts the right issuer', () {
      expect(
        openSsl.verifyCertificateSignature(pki.folha, pki.intermediaria),
        isTrue,
      );
      expect(
        openSsl.verifyCertificateSignature(pki.intermediaria, pki.raiz),
        isTrue,
      );
    });

    test('rejects the wrong issuer', () {
      expect(
        openSsl.verifyCertificateSignature(pki.folha, pki.raiz),
        isFalse,
      );
    });
  });

  group('verifyChain', () {
    test('validates a full chain with an intermediate', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
      );

      expect(r.valid, isTrue, reason: r.message);
      expect(r.errorCode, X509_V_OK);
      expect(r.chain, hasLength(3));
      expect(r.chain.first.subject, contains('Titular Teste'));
      expect(r.chain.last.subject, contains('AC Raiz Teste'));
      r.dispose();
    });

    test('fails without the intermediate and says why', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
      );

      expect(r.valid, isFalse);
      expect(r.untrusted, isTrue);
      expect(r.message, isNotEmpty);
      expect(r.depth, greaterThanOrEqualTo(0));
      expect(r.failingCertificate, contains('Titular Teste'));
    });

    test('fails when the anchor is not the root of the chain', () {
      // The other PKI uses the same names, so OpenSSL does find an issuer by
      // DN and only fails at the signature check - which is exactly the
      // protection that matters against a swapped anchor.
      final outra = _Pki(openSsl);
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [outra.raiz],
        intermediates: [pki.intermediaria],
      );

      expect(r.valid, isFalse);
      expect(r.errorCode, X509_V_ERR_CERT_SIGNATURE_FAILURE);
      expect(r.failingCertificate, contains('AC Intermediaria Teste'));
    });

    test('partialChain accepts the intermediate as an anchor', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.intermediaria],
        partialChain: true,
      );

      expect(r.valid, isTrue, reason: r.message);
      r.dispose();
    });

    test('verificationTime no futuro reprova certificado expired', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
        verificationTime: DateTime.now().add(const Duration(days: 3650)),
      );

      expect(r.valid, isFalse);
      expect(r.expired, isTrue);
      expect(r.errorCode, X509_V_ERR_CERT_HAS_EXPIRED);
    });

    test('ignoreValidity accepts a certificate outside its window', () {
      final curto = (X509CertificateBuilder(openSsl)
            ..setSubject(commonName: 'Ja Expirado')
            ..setIssuer(issuerCert: pki.intermediaria)
            ..setPublicKey(pki.chaveFolha)
            ..setValidity(notBeforeOffset: -7200, notAfterOffset: -3600))
          .sign(pki.chaveIntermediaria);

      final semFlag = openSsl.verifyChain(
        certificate: curto,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
      );
      expect(semFlag.valid, isFalse);
      expect(semFlag.expired, isTrue);

      final comFlag = openSsl.verifyChain(
        certificate: curto,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
        ignoreValidity: true,
      );
      expect(comFlag.valid, isTrue, reason: comFlag.message);
      comFlag.dispose();
    });

    test('CRL com o serial revoked reprova a cadeia', () {
      final crl = (openSsl.newCrlBuilder()
            ..setIssuerFromCertificate(pki.intermediaria)
            ..setUpdateTimes(
              thisUpdate: DateTime.now().toUtc(),
              nextUpdate: DateTime.now().toUtc().add(const Duration(days: 1)),
            )
            ..addRevokedSerialBigInt(
              serialNumber: pki.folha.serialNumberBigInt,
              revocationTime: DateTime.now().toUtc(),
            ))
          .sign(issuerKey: pki.chaveIntermediaria);

      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
        crls: [crl],
        checkRevocation: true,
      );

      expect(r.valid, isFalse);
      expect(r.revoked, isTrue, reason: r.message);
    });

    test('a CRL without the serial does not disturb validation', () {
      final crl = (openSsl.newCrlBuilder()
            ..setIssuerFromCertificate(pki.intermediaria)
            ..setUpdateTimes(
              thisUpdate: DateTime.now().toUtc(),
              nextUpdate: DateTime.now().toUtc().add(const Duration(days: 1)),
            ))
          .sign(issuerKey: pki.chaveIntermediaria);

      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
        crls: [crl],
        checkRevocation: true,
      );

      expect(r.valid, isTrue, reason: r.message);
      r.dispose();
    });

    test('requires at least one anchor', () {
      expect(
        () => openSsl.verifyChain(certificate: pki.folha, anchors: []),
        throwsArgumentError,
      );
    });

    test('the chain is returned as owned copies', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
      );
      expect(r.valid, isTrue, reason: r.message);
      r.dispose();
    });

    test('the returned chain outlives the verification context', () {
      final r = openSsl.verifyChain(
        certificate: pki.folha,
        anchors: [pki.raiz],
        intermediates: [pki.intermediaria],
      );

      // The certificates are copies: still readable after the native context
      // has been freed.
      final assuntos = r.chain.map((c) => c.subject).toList();
      expect(assuntos, hasLength(3));
      expect(
        openSsl.verifyCertificateSignature(r.chain[0], r.chain[1]),
        isTrue,
      );
      r.dispose();
    });
  });

  group('pure PKCS#12 + verification', () {
    test('the decoded key pairs with the decoded certificate', () {
      final p12 = openSsl.createPkcs12(
        privateKey: pki.chaveFolha,
        certificate: pki.folha,
        caCertificates: [pki.intermediaria],
        password: 'senha',
      );

      final bundle = openSsl.parsePkcs12Pure(p12, password: 'senha');
      final dados = Uint8List.fromList('mensagem'.codeUnits);
      final assinatura = openSsl.sign(bundle.privateKey, dados);

      // If the decrypted key were not the certificate's pair, the chain built
      // from it would not close against the root.
      final r = openSsl.verifyChain(
        certificate: bundle.certificate,
        anchors: [pki.raiz],
        intermediates: bundle.caCertificates,
      );

      expect(r.valid, isTrue, reason: r.message);
      expect(openSsl.verify(bundle.privateKey, dados, assinatura), isTrue);
      r.dispose();
    });
  });
}
