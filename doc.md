# OpenSSL Bindings para Dart

Esta biblioteca fornece bindings FFI robustos e idiomáticos para a biblioteca OpenSSL 3.x, permitindo operações criptográficas avançadas, geração de certificadose comunicação segura (TLS/DTLS) diretamente via Dart. 

O foco é fornecer uma camada de abstração segura, evitando vazamentos de memória (memory safe) e oferecendo flexibilidade para carregar bibliotecas dinâmicas de locais personalizados.

## Funcionalidades Principais

### Infraestrutura e Segurança
*   **Carregamento Flexível**: Carrega `libcrypto` e `libssl` do sistema (PATH), de variáveis de ambiente, ou de **caminhos explícitos** definidos em tempo de execução.
*   **Memory Safety**: Gerenciamento automático de memória para estruturas nativas (BIOs, X509, EVP_PKEY, Strings), prevenindo leaks.
*   **GitHub Actions**: Testes automatizados em Windows.

### X.509 e PKI
*   **Parsing Completo**: Leitura de versão, serial, validade (`notBefore`, `notAfter` com parsing robusto via `tm` struct), Subject, Issuer.
*   **Builders Fluentes**:
    *   `X509CertificateBuilder`: Criação de certificados (Self-Signed ou CA-Signed).
    *   `X509RequestBuilder`: Geração de CSR (Certificate Signing Request).
*   **Formatos**: Suporte a PEM e DER.

### Criptografia e Assinatura (CMS/PAdES)
*   **Chaves**: Geração e carregamento de RSA/EVP keys (PEM/DER/Encrypted PEM).
*   **CMS/PKCS#7**:
    *   Assinatura "Detached" (essencial para PAdES/CAdES).
    *   Suporte a **Signed Attributes** (customizáveis).
    *   Verificação de assinaturas CMS com certificados de confiança (TrustStore).
    *   Assinatura de Digests pré-calculados (para fluxos de "Network Restocking").

### Networking Seguro (TLS & DTLS)
*   **TLS Assíncrono**: `SecureSocketOpenSSLAsync` (API similar a `dart:io`).
*   **TLS Síncrono**: `SecureSocketOpenSSLSync` (blocado, útil para tunnels/proxies).
*   **DTLS 1.2+**: `DtlsClient` e `DtlsServer` sobre UDP.
*   **Path Injection**: Todos os sockets aceitam caminhos customizados para `libcrypto` e `libssl`, facilitando o deploy embarcado.

---

## Configuração

Adicione ao `pubspec.yaml`:
```yaml
dependencies:
  openssl_bindings:
    path: .
```

Requer **OpenSSL 3.0+**. No Windows, instale via [Win64OpenSSL](https://slproweb.com/products/Win32OpenSSL.html).

---

## Exemplos de Uso

### 1. Inicialização e Caminhos Customizados

A classe `OpenSSL` é o ponto de entrada. Você pode especificar onde as DLLs estão localizadas:

```dart
import 'package:openssl_bindings/src/api/openssl.dart';

// Uso padrão (busca no PATH ou variáveis de ambiente)
final openssl = OpenSSL();

// Uso com caminhos específicos (ex: deploy com binários locais)
final opensslCustom = OpenSSL(
  cryptoPath: r'C:\App\libs\libcrypto-3-x64.dll',
  sslPath:    r'C:\App\libs\libssl-3-x64.dll',
);
```

### 2. X.509 e Dates

Parsing robusto de datas e versão:

```dart
final cert = openssl.x509FromPem(pemString);

print("Versão: ${cert.version}"); // Ex: 3
print("Serial: ${cert.serialNumber}");
print("Válido de: ${cert.notBefore} até ${cert.notAfter}");

// Acesso ao Subject/Issuer como Strings formatadas
print("Subject: ${cert.subject.debugString()}"); 
```

### 3. Gerando Certificados (Builder)

```dart
import 'package:openssl_bindings/src/x509/x509_builder.dart';

// 1. Gerar Chave
final key = openssl.generateRsaKey(2048);

// 2. Configurar Builder
final builder = X509CertificateBuilder(openssl)
  ..setSerialNumber(123456)
  ..setVersion(3)
  ..setValidity(days: 365)
  ..setSubject(commonName: 'MyApp Root CA', country: 'BR')
  ..setIssuerAsSubject() // Self-Signed
  ..setPublicKey(key);

// 3. Assinar e Exportar
builder.sign(key, digest: 'sha256');
final cert = builder.build();

print(cert.toPem());
```

### 4. CMS/PAdES (Assinatura Digital)

Para assinar documentos (PDF/PAdES) ou dados genéricos:

```dart
import 'package:openssl_bindings/src/cms/cms_pkcs7_signer.dart';

final signer = CmsPkcs7Signer(openssl);

// Assinatura Detached (O CMS contém apenas a assinatura, não o arquivo original)
final signatureDer = signer.signDetached(
  content: fileBytes,
  certificateDer: myCertBytes,
  privateKey: myPrivateKey,
); // Retorna bytes DER do CMS

// Assinar Hash (Se você já calculou o SHA-256 externamente)
final digest = openssl.sha256(fileBytes);
final sigFromHash = signer.signDetachedDigest(
  contentDigest: digest,
  certificateDer: myCertBytes,
  privateKey: myPrivateKey,
);
```

### 5. DTLS (UDP Seguro) com DLLs Customizadas

Exemplo de Cliente DTLS injetando caminhos das bibliotecas:

```dart
import 'package:openssl_bindings/src/dtls/dtls_client.dart';

void main() async {
  final client = DtlsClient(
    cryptoPath: r'./libs/libcrypto.dll',
    sslPath:    r'./libs/libssl.dll',
  );

  final connection = await client.connect(
    InternetAddress('127.0.0.1'), 
    4433,
    pskIdentity: 'user',
    pskKey: 'password', // Ou usar certificados
  );

  connection.send(Uint8List.fromList('Hello DTLS'.codeUnits));
  
  connection.listen((data) {
    print('Recebido: ${String.fromCharCodes(data)}');
  });
}
```

### 6. TLS TCP Assíncrono

```dart
import 'package:openssl_bindings/src/ssl/secure_socket_openssl_async.dart';

// Factory aceita caminhos opcionais também
final socket = await SecureSocketOpenSSLAsync.connect(
  'google.com', 443,
  // cryptoPath: ..., sslPath: ...
);

await socket.send(utf8.encode('GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'));
```

### 7. Criptografia Geral (KDF, Hashing e HMAC)

Funcionalidades genéricas de criptografia para complementar o uso de PKI.

**PBKDF2 (Key Derivation):**

```dart
final salt = utf8.encode('salt_randomico');
final password = utf8.encode('minha_senha_secreta');

// Deriva uma chave de 256 bits (32 bytes) usando HMAC-SHA256
final key = openssl.pbkdf2(
  password: Uint8List.fromList(password), 
  salt: Uint8List.fromList(salt), 
  iterations: 10000, 
  keyLength: 32
);
```

**Hashing e HMAC:**

```dart
final data = utf8.encode('Mensagem Importante');
final secret = utf8.encode('segredo');

// Hash Genérico (suporta algoritmos disponíveis no OpenSSL: sha256, sha512, sha3-256, etc)
final digest = openssl.digest('sha256', Uint8List.fromList(data));

// HMAC
final mac = openssl.hmac('sha256', Uint8List.fromList(secret), Uint8List.fromList(data));
```

**AES-256-CBC (PKCS#7):**

```dart
final key = openssl.pbkdf2(
  password: Uint8List.fromList(utf8.encode('senha')),
  salt: Uint8List.fromList(utf8.encode('salt')),
  iterations: 20000,
  keyLength: 32,
);
final iv = Uint8List.fromList(List<int>.generate(16, (i) => i));

final ciphertext = openssl.aes256CbcEncrypt(
  data: Uint8List.fromList(utf8.encode('segredo')),
  key: key,
  iv: iv,
);

final plaintext = openssl.aes256CbcDecrypt(
  ciphertext: ciphertext,
  key: key,
  iv: iv,
);
```

### 8. Curvas Elípticas (ECC)

Geração de chaves EC modernas (P-256, P-384, etc).

```dart
// Gera uma chave usando a curva prime256v1 (NIST P-256)
final key = openssl.generateEc('prime256v1');

print(key.toPrivateKeyPem());
```
