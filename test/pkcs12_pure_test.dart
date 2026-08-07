import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';
import 'package:openssl_bindings/src/pkcs/pure/block_ciphers.dart';
import 'package:openssl_bindings/src/pkcs/pure/der.dart';
import 'package:openssl_bindings/src/pkcs/pure/digests.dart';

Uint8List _hex(String h) => Uint8List.fromList([
      for (var i = 0; i < h.length; i += 2)
        int.parse(h.substring(i, i + 2), radix: 16),
    ]);

String _hexOf(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('Pure primitives', () {
    test('SHA-1 and SHA-256 match the FIPS vectors', () {
      final abc = Uint8List.fromList('abc'.codeUnits);
      expect(_hexOf(sha1Digest(abc)),
          'a9993e364706816aba3e25717850c26c9cd0d89d');
      expect(_hexOf(sha1Digest(Uint8List(0))),
          'da39a3ee5e6b4b0d3255bfef95601890afd80709');
      expect(
        _hexOf(sha256Digest(abc)),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('HMAC-SHA1 matches RFC 2202', () {
      final chave = Uint8List.fromList(List.filled(20, 0x0b));
      expect(
        _hexOf(hmac(PureHash.sha1, chave,
            Uint8List.fromList('Hi There'.codeUnits))),
        'b617318655057264e28bc0b6fb378c8ef146be00',
      );
    });

    test('PBKDF2-HMAC-SHA1 matches RFC 6070', () {
      expect(
        _hexOf(pbkdf2(
          PureHash.sha1,
          Uint8List.fromList('password'.codeUnits),
          Uint8List.fromList('salt'.codeUnits),
          4096,
          20,
        )),
        '4b007901b765489abead49d926f721d065a429c1',
      );
    });

    test('RC2 matches the RFC 2268 vectors', () {
      final casos = <(String, int, String, String)>[
        ('0000000000000000', 64, '0000000000000000', 'ebb773f993278eff'),
        ('ffffffffffffffff', 64, 'ffffffffffffffff', '278b27e42e2f0d49'),
        ('3000000000000000', 64, '1000000000000001', '30649edf9be7d2c2'),
        ('88', 64, '0000000000000000', '61a8a244adacccf0'),
        ('88bca90e90875a', 64, '0000000000000000', '6ccf4308974c267f'),
        ('88bca90e90875a7f0f79c384627bafb2', 128, '0000000000000000',
            '2269552ab0f85ca6'),
      ];

      for (final (chave, bits, claro, cifrado) in casos) {
        final rc2 = Rc2Cipher(_hex(chave), bits);
        expect(_hexOf(rc2.decryptBlock(_hex(cifrado))), claro,
            reason: 'chave $chave / $bits bits');
      }
    });

    test('DES and 3DES match the known vectors', () {
      final des = DesCipher(_hex('133457799BBCDFF1'));
      expect(_hexOf(des.encryptBlock(_hex('0123456789ABCDEF'))),
          '85e813540f0ab405');
      expect(_hexOf(des.decryptBlock(_hex('85E813540F0AB405'))),
          '0123456789abcdef');

      final tdes = TripleDesCipher(
          _hex('0123456789abcdef23456789abcdef01456789abcdef0123'));
      expect(_hexOf(tdes.decryptBlock(_hex('a826fd8ce53b855f'))),
          '5468652071756663');
    });

    test('AES matches the FIPS-197 vectors', () {
      const claro = '00112233445566778899aabbccddeeff';
      expect(
        _hexOf(AesCipher(_hex('000102030405060708090a0b0c0d0e0f'))
            .decryptBlock(_hex('69c4e0d86a7b0430d8cdb78070b4c55a'))),
        claro,
      );
      expect(
        _hexOf(AesCipher(_hex('000102030405060708090a0b0c0d0e0f1011121314151617'))
            .decryptBlock(_hex('dda97ca4864cdfe06eaf70a0ec0d7191'))),
        claro,
      );
      expect(
        _hexOf(AesCipher(_hex(
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))
            .decryptBlock(_hex('8ea2b7ca516745bfeafc49904b496089'))),
        claro,
      );
    });

    test('the DER reader handles OID, integer and nesting', () {
      // SEQUENCE { OID 1.2.840.113549.1.12.1.6, INTEGER 2048 }
      final der = _hex('3010060a2a864886f70d010c010602020800');
      final seq = readDer(der);
      expect(seq.tag, 0x30);
      expect(seq.constructed, isTrue);

      final filhos = seq.elements;
      expect(filhos, hasLength(2));
      expect(filhos[0].oid, '1.2.840.113549.1.12.1.6');
      expect(filhos[1].asInt, 2048);
    });

    test('the DER reader rejects a truncated buffer', () {
      expect(() => readDer(_hex('3010060a2a86')), throwsFormatException);
    });
  });

  group('decodePkcs12Pure', () {
    final arquivo = File('test/fixtures/legacy_rc2_40.p12');
    late Uint8List der;

    setUp(() => der = arquivo.readAsBytesSync());

    test('opens a 40-bit RC2 PKCS#12 without the legacy provider', () {
      final bundle = decodePkcs12Pure(der, password: 'senha123');

      expect(bundle.privateKeyPem, startsWith('-----BEGIN PRIVATE KEY-----'));
      expect(bundle.certificatePem, startsWith('-----BEGIN CERTIFICATE-----'));
      expect(bundle.friendlyName, 'fixture');
    });

    test('the result is accepted by OpenSSL and is the matching pair', () {
      final openSsl = OpenSSL();
      final bundle = decodePkcs12Pure(der, password: 'senha123');

      final cert = openSsl.loadCertificatePem(bundle.certificatePem);
      expect(cert.subject, contains('Legacy P12 Fixture'));

      // Signing with the key and verifying with the certificate's public key
      // proves decryption produced exactly the pair stored in the file.
      final chave = openSsl.loadPrivateKeyPem(bundle.privateKeyPem);
      final dados = Uint8List.fromList('conteudo de teste'.codeUnits);
      final assinatura = openSsl.sign(chave, dados);
      expect(openSsl.verify(cert.publicKey, dados, assinatura), isTrue);
    });

    test('a wrong password fails the MAC check', () {
      expect(
        () => decodePkcs12Pure(der, password: 'errada'),
        throwsA(
          isA<PurePkcs12Exception>().having(
            (e) => e.message,
            'message',
            contains('MAC'),
          ),
        ),
      );
    });

    test('an invalid file is rejected with a clear message', () {
      expect(
        () => decodePkcs12Pure(
          Uint8List.fromList([1, 2, 3, 4]),
          password: 'x',
        ),
        throwsA(isA<PurePkcs12Exception>()),
      );
    });

    test('also opens a modern PKCS#12 created by this package', () {
      final openSsl = OpenSSL();
      final chave = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl)
        ..setSubject(commonName: 'P12 Moderno Puro')
        ..setIssuerAsSubject()
        ..setPublicKey(chave)
        ..setValidity(notAfterOffset: 3600);
      final cert = builder.sign(chave);

      final p12 = openSsl.createPkcs12(
        privateKey: chave,
        certificate: cert,
        password: 'abc123',
      );

      final bundle = decodePkcs12Pure(p12, password: 'abc123');
      final certLido = openSsl.loadCertificatePem(bundle.certificatePem);
      expect(certLido.subject, contains('P12 Moderno Puro'));
    });

    test('parsePkcs12Pure returns the same bundle as the FFI API', () {
      final openSsl = OpenSSL();
      final bundle = openSsl.parsePkcs12Pure(der, password: 'senha123');

      expect(bundle.certificate.subject, contains('Legacy P12 Fixture'));
      expect(bundle.caCertificates, isEmpty);
    });

    test('parsePkcs12(autoLegacy: true) opens with no configuration', () {
      final openSsl = OpenSSL();
      final bundle = openSsl.parsePkcs12(
        der,
        password: 'senha123',
        autoLegacy: true,
      );

      expect(bundle.certificate.subject, contains('Legacy P12 Fixture'));
    });
  });
}
