# OpenSSL Bindings for Dart

[![Dart CI](https://github.com/insinfo/dart_openssl_bindings/actions/workflows/dart.yml/badge.svg)](https://github.com/insinfo/dart_openssl_bindings/actions/workflows/dart.yml)

Robust and idiomatic FFI bindings for **OpenSSL 3.x** in Dart. This library provides advanced cryptographic operations, X.509 certificate generation/parsing, and secure networking (TLS/DTLS) directly via Dart FFI, without requiring native compilation steps (beyond having OpenSSL installed/available).

It focuses on **memory safety** (automatic resource management), **flexibility** (customizable DLL paths), and providing a clean Object-Oriented API.

## Core Features

### Infrastructure & Security
*   **Flexible Loading**: Load `libcrypto` and `libssl` from system paths, environment variables, or **explicit paths** defined at runtime (ideal for bundled apps).
*   **Memory Safety**: Automatic memory management for native structures using Dart's `Finalizer` to prevent leaks.
*   **CI Tested**: Verified across Windows and Linux environments.

### X.509 & PKI
*   **Complete Parsing**: Read Version, Serial, Validity (`notBefore`, `notAfter`), Subject, and Issuer.
*   **Fluent Builders**:
    *   `X509CertificateBuilder`: Create Self-Signed or CA-Signed certificates.
    *   `X509RequestBuilder`: Generate CSRs (Certificate Signing Requests).
*   **Formats**: Full support for PEM and DER.

### Cryptography & Signing (CMS/PAdES)
*   **Key Management**: Generate and load RSA/EVP keys (PEM/DER/Encrypted PEM).
*   **CMS/PKCS#7**:
    *   **Detached Signatures**: Critical for PAdES/CAdES standards.
    *   **External Digest Signing**: Support for signing pre-calculated hashes (e.g., for Hardware Security Modules or remote signing flows).
    *   **Verification**: Verify CMS signatures against Trusted Root stores.

### Secure Networking (TLS & DTLS)
*   **Async TLS**: `SecureSocketOpenSslAsync` (API compatible with `dart:io` Socket).
*   **Sync TLS**: `SecureSocketOpenSslSync` (Blocking API, useful for tunnels/proxies).
*   **DTLS 1.2+**: Full support for `DtlsClient` and `DtlsServer` over UDP.

---

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  openssl_bindings: any   
```

### Requirements
*   **Dart SDK**: 3.0+
*   **OpenSSL**: Version 3.0 or higher.
    *   **Windows**: Recommended [Win64OpenSSL](https://slproweb.com/products/Win32OpenSSL.html).
    *   **Linux**: `sudo apt-get install libssl-dev` (or equivalent).

---

## Usage Examples

### 1. Initialization and Custom Paths

The `OpenSSL` class is the main entry point. You can let it find the library automatically or inject specific paths.

```dart
import 'package:openssl_bindings/openssl.dart';

// 1. Standard usage (uses PATH or env vars)
final openssl = OpenSSL();

// 2. Custom usage (e.g., bundling binaries with your app)
final opensslCustom = OpenSSL(
  cryptoPath: r'./libs/libcrypto-3-x64.dll',
  sslPath:    r'./libs/libssl-3-x64.dll',
);
```

### 2. Generating Certificates (X509 Builder)

Easily create RSA keys and self-signed certificates.

```dart
import 'package:openssl_bindings/openssl.dart';

// Generate RSA Key
final key = openssl.generateRsa(2048);

// Configure the Certificate
final builder = X509CertificateBuilder(openssl)
  ..setSerialNumber(1001)
  ..setValidity(notBeforeOffset: 0, notAfterOffset: 31536000) // 1 year
  ..setSubject(commonName: 'My App Root CA', country: 'US')
  ..setIssuerAsSubject()   // Self-signed
  ..setPublicKey(key);

// Sign and export
final cert = builder.sign(key, hashAlgorithm: 'SHA256');

print(cert.toPem());
print(key.toPrivateKeyPem());
```

### 3. CMS/PAdES Signing (Detached)

Create digital signatures for documents (like PDF/PAdES) where the signature is separate from the content.

```dart
import 'package:openssl_bindings/openssl.dart';

final signer = CmsPkcs7Signer(openssl);

// Detached Signature (CMS contains only the signature, not the file content)
final signatureDer = signer.signDetached(
  content: fileBytes,
  certificateDer: myCertBytes,
  privateKey: myPrivateKey,
);

// Verify
final isValid = openssl.verifyCmsDetached(
  cmsDer: signatureDer,
  content: fileBytes,
  trustedCertDer: rootCaBytes,
);
```

### 4. Secure Networking (DTLS Client)

Example of a DTLS client connecting to a server, using custom library paths.

```dart
import 'package:openssl_bindings/openssl.dart';

void main() async {
  // Initialize DTLS with custom OpenSSL paths
  final client = DtlsClient(
    cryptoPath: r'./libs/libcrypto.so',
    sslPath:    r'./libs/libssl.so',
  );

  final connection = await client.connect(
    InternetAddress('127.0.0.1'), 
    4433,
    pskIdentity: 'user',
    pskKey: 'password', // Or use certificates
  );

  print('Connected via DTLS!');
  
  connection.listen((data) {
    print('Received: ${String.fromCharCodes(data)}');
  });
  
  connection.send(Uint8List.fromList('Hello DTLS'.codeUnits));
}
```

### 5. Async TLS Client (TCP)

```dart
import 'package:openssl_bindings/openssl.dart';

final socket = await SecureSocketOpenSslAsync.connect('example.com', 443);

await socket.send(utf8.encode('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'));

socket.listen((data) {
  print(utf8.decode(data));
});
```
