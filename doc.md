# OpenSSL Bindings para Dart

Esta biblioteca fornece bindings FFI para a biblioteca OpenSSL, permitindo operações criptográficas avançadas e comunicação segura (TLS) diretamente via Dart, sem dependências nativas compiladas além das DLLs do OpenSSL instaladas no sistema.

## Funcionalidades Implementadas

### Criptografia e Chaves
*   **Carregamento Dinâmico**: Carrega `libcrypto` e `libssl` do sistema ou de caminhos especificados.
*   **Geração de Chaves**: Suporte para geração de pares de chaves RSA (via `EvpPkey`).
*   **Exportação PEM**: Exportação de chaves privadas e públicas para formato PEM.

### X.509 e PKI
*   **Certificados X.509**:
    *   Criação de certificados V3.
    *   Certificados Auto-assinados (Self-Signed).
    *   Definição de Serial, Validade, Subject e Issuer.
    *   Exportação para PEM.
*   **CSR (Certificate Signing Requests)**:
    *   Criação de requisições de assinatura.
    *   Definição de Subject e Public Key.
    *   Assinatura do CSR.
    *   Exportação para PEM.
*   **Assinatura de Certificados**:
    *   Assinatura de certificados usando uma CA (Issuer Key/Cert) ou Auto-assinatura.

### TLS / SSL
*   **SecureSocketOpenSSLAsync**: Implementação de Socket TLS assíncrono (compatível com `dart:io`).
*   **SecureSocketOpenSSLSync**: Implementação de Socket TLS síncrono.
*   **Modos**: Cliente e Servidor.
*   **Arquitetura BIO**: Utiliza BIOs de memória do OpenSSL para total controle sobre o fluxo de dados, desacoplando a criptografia do transporte de rede.

## Instalação

Adicione ao seu `pubspec.yaml`:

```yaml
dependencies:
  openssl_bindings:
    path: . # ou git/pub
```

Certifique-se de ter o OpenSSL 3.x instalado. No Windows, recomenda-se as distribuições [Win64OpenSSL](https://slproweb.com/products/Win32OpenSSL.html).

As variáveis de ambiente podem ser usadas para apontar para as DLLs:
*   `OPENSSL_LIBCRYPTO_PATH`
*   `OPENSSL_LIBSSL_PATH`

## Exemplos de Uso

### 1. Inicialização

```dart
import 'package:openssl_bindings/src/api/openssl.dart';

final openssl = OpenSSL();
```

### 2. Gerando um Certificado Auto-Assinado

```dart
import 'package:openssl_bindings/src/x509/x509_builder.dart';

// Gerar chave RSA
final key = openssl.generateRsaKey(2048);

// Configurar o Builder
final builder = X509CertificateBuilder(openssl);
builder.setSerialNumber(1001);
builder.setValidity(notAfterOffset: 365 * 24 * 3600); // 1 ano
builder.setSubject(
  commonName: 'localhost',
  organization: 'Minha Empresa Ltda',
  country: 'BR'
);
builder.setIssuerAsSubject(); // Self-signed
builder.setPublicKey(key);

// Assinar
builder.sign(key);

// Obter certificado
final cert = builder.build();

// Exportar
print(key.toPrivateKeyPem());
print(cert.toPem());
```

### 3. Cliente/Servidor TLS

Do lado do **Servidor**:

```dart
import 'dart:io';
import 'package:openssl_bindings/src/ssl/secure_socket_openssl_async.dart';

void startServer(String certPath, String keyPath) async {
  final server = await ServerSocket.bind('127.0.0.1', 8443);
  print('Servidor ouvindo na 8443...');

  server.listen((socket) async {
    try {
      final secureSocket = SecureSocketOpenSSLAsync.serverFromSocket(
        socket,
        certFile: certPath,
        keyFile: keyPath,
      );
      
      // Handshake acontece automaticamente ou sob demanda
      await secureSocket.ensureHandshakeCompleted();
      
      final data = await secureSocket.recv(1024);
      print('Recebido: ${String.fromCharCodes(data)}');
      
      await secureSocket.send(Uint8List.fromList('Olá TLS!'.codeUnits));
      await secureSocket.close();
    } catch (e) {
      print('Erro TLS: $e');
    }
  });
}
```

Do lado do **Cliente**:

```dart
import 'package:openssl_bindings/src/ssl/secure_socket_openssl_async.dart';

void runClient() async {
  final socket = await SecureSocketOpenSSLAsync.connect('127.0.0.1', 8443);
  
  await socket.send(Uint8List.fromList('Hello Server'.codeUnits));
  
  final response = await socket.recv(1024);
  print('Resposta: ${String.fromCharCodes(response)}');
  
  await socket.close();
}
```

### 4. CMS/PKCS#7 (Assinatura Detached)

Assinar **conteúdo bruto** (OpenSSL calcula o digest):

```dart
import 'dart:typed_data';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/cms/cms_pkcs7_signer.dart';

final openssl = OpenSSL();

// Carregue a chave e o certificado
final key = openssl.loadPrivateKeyPem(privateKeyPem);
final certDer = Uint8List.fromList(certDerBytes);

final signer = CmsPkcs7Signer(openssl);
final signature = signer.signDetached(
  content: Uint8List.fromList(contentBytes),
  certificateDer: certDer,
  privateKey: key,
);
```

Assinar **hash pré-calculado** (use quando seu fluxo já produz digest):

```dart
import 'dart:typed_data';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/cms/cms_pkcs7_signer.dart';

final openssl = OpenSSL();
final key = openssl.loadPrivateKeyPem(privateKeyPem);
final certDer = Uint8List.fromList(certDerBytes);

final digest = openssl.sha256(contentBytes);

final signer = CmsPkcs7Signer(openssl);
final signature = signer.signDetachedDigest(
  contentDigest: digest,
  certificateDer: certDer,
  privateKey: key,
);
```

### 5. CMS: decode/encode + verify

```dart
import 'dart:typed_data';
import 'package:openssl_bindings/src/api/openssl.dart';

final openssl = OpenSSL();

final cms = openssl.decodeCms(cmsDerBytes);
final cmsDer = openssl.encodeCms(cms);

final ok = openssl.verifyCmsDetached(
  cmsDer: cmsDer,
  content: Uint8List.fromList(contentBytes),
  trustedCertDer: Uint8List.fromList(certDerBytes),
);
```
