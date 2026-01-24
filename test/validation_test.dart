import 'dart:io';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:openssl_bindings/openssl.dart';


/// Teste de Validação das Funcionalidades Prioritárias
/// 1. Chaves Criptogradas (Senha)
/// 2. Detalhes de X509 (Subject, Issuer, Serial)
/// 3. Assinatura de Hash (Digest Signing)
/// 4. Validação com Trust Store
void main() {
  group('Funcionalidades Prioritárias', () {
    late OpenSSL openSsl;
    late Directory tempDir;

    setUpAll(() async {
      // Ajuste o caminho da DLL se necessário para rodar localmente
      openSsl = OpenSSL();
      tempDir = await Directory.systemTemp.createTemp('openssl_validacao_');
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    // 1. Encrypted Private Keys
    test('Deve salvar e carregar chave privada com senha', () {
      final pkey = openSsl.generateRsa(2048);

      // Salvar com senha (PKCS#8)
      const password = 'senha-secreta';
      final pemEncrypted = pkey.toPrivateKeyPem(password: password);
      expect(pemEncrypted, contains('BEGIN ENCRYPTED PRIVATE KEY'));

      // Carregar com senha
      final loaded = openSsl.loadPrivateKeyPem(pemEncrypted, password: password);

      // Validar assinatura com a chave carregada e verificação com a chave original
      final data = Uint8List.fromList('teste de assinatura'.codeUnits);
      final signature = openSsl.sign(loaded, data);
      final isValid = openSsl.verify(pkey, data, signature);
      expect(isValid, isTrue);

      // Senha incorreta deve falhar
      expect(
        () => openSsl.loadPrivateKeyPem(pemEncrypted, password: 'senha-errada'),
        throwsA(isA<OpenSslException>()),
      );
    }, );//skip: 'Skipped for debugging'

    // 2. X509 Details
    test('Deve ler detalhes do Certificado (Subject, Issuer, Serial, Validity)', () {
      final pkey = openSsl.generateRsa(2048);
      final builder = X509CertificateBuilder(openSsl);
      
      builder.setSubject(
        commonName: 'Test Cert',
        organization: 'Test Org',
        country: 'BR',
      );
      builder.setIssuer(
        commonName: 'Test CA',
        organization: 'CA Org',
        country: 'US',
      );
      builder.setSerialNumber(123456);
      builder.setValidity(notBeforeOffset: 0, notAfterOffset: 3600);
      builder.setPublicKey(pkey);
      
      final cert = builder.sign(pkey); // Self-signed (assinatura valida, mas issuer difere se forçando)
      // Nota: setIssuer so funciona se assinado por chave correspondente ao issuer name se quisermos validar.
      // Mas para apenas ler os campos, ok.

      expect(cert.subject, contains('CN=Test Cert'));
      expect(cert.subject, contains('C=BR'));
      expect(cert.issuer, contains('CN=Test CA'));
      expect(cert.serialNumber, equals('123456'));
      
      expect(cert.notBefore, isNotNull);
      expect(cert.notAfter, isNotNull);
      expect(cert.notAfter!.isAfter(cert.notBefore!), isTrue);
    }, );//skip: 'Skipped for debugging'

    // 3. CMS Detached Signing & 4. Verificação de Assinatura
    test('Deve assinar (Detached) e verificar assinatura', () {
      // a) Setup: CA Root e Chave
      final caKey = openSsl.generateRsa(2048);
      final caBuilder = X509CertificateBuilder(openSsl);
      caBuilder.setSubject(commonName: 'My Root CA');
      caBuilder.setIssuerAsSubject();
      caBuilder.setPublicKey(caKey);
      caBuilder.sign(caKey);

      // b) Setup: User Key e Cert (assinado pela CA)
      final userKey = openSsl.generateRsa(2048);
      final userBuilder = X509CertificateBuilder(openSsl);
      userBuilder.setSubject(commonName: 'User Signer');
      // Set Issuer name to match CA Subject
      // Como não temos getter de Subject X509Name object, usamos string parsing ou setamos manual.
      // O builder.setIssuer usa string.
      userBuilder.setIssuer(commonName: 'My Root CA'); 
      userBuilder.setPublicKey(userKey);
      
      // Assinar com a chave da CA!
      final userCert = userBuilder.sign(caKey);

      // c) Content
      final content = Uint8List.fromList('Conteudo Importante do PDF'.codeUnits);

      // d) Detached Signing
      final cms = openSsl.signDetachedContentInfo(
        content: content,
        certificate: userCert,
        privateKey: userKey,
      );

      expect(cms.handle, isNot(nullptr));

      // e) Verificação da assinatura (sem validar cadeia)
      final isValid = openSsl.verifyCmsDetachedSignatureOnly(
        cms: cms,
        content: content,
      );

      expect(isValid, isTrue, reason: 'A verificação da assinatura deve passar');
    }, );//skip: 'Skipped for debugging'
  });
}
