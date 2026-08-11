# OpenSSL Bindings for Dart

[![Dart CI](https://github.com/insinfo/dart_openssl_bindings/actions/workflows/dart.yml/badge.svg)](https://github.com/insinfo/dart_openssl_bindings/actions/workflows/dart.yml)
[![codecov](https://codecov.io/gh/insinfo/dart_openssl_bindings/branch/main/graph/badge.svg)](https://codecov.io/gh/insinfo/dart_openssl_bindings)

Robust and idiomatic FFI bindings for **OpenSSL 3.x** in Dart. This library provides advanced cryptographic operations, X.509 certificate generation/parsing, and secure networking (TLS/DTLS) directly via Dart FFI, without requiring native compilation steps (beyond having OpenSSL installed/available).

It focuses on **memory safety** (automatic resource management), **flexibility** (customizable DLL paths), and providing a clean object-oriented API.

## Core Features

### Infrastructure & Security
*   **Flexible Loading**: Load `libcrypto` and `libssl` from system paths, environment variables, or **explicit paths** defined at runtime (ideal for bundled apps).
*   **Memory Safety**: Automatic memory management for native structures using Dart's `Finalizer` to prevent leaks.
*   **CI Tested**: Verified across Windows and Linux environments.

### X.509 & PKI
*   **Complete Parsing**: Read Version, Serial, Validity (`notBefore`, `notAfter`), Subject, and Issuer.
*   **Large Serial Support (ASN.1/BN)**:
  *   `x509GetSerialBytes`, `x509GetSerialHex`, `x509GetSerialDecimal`.
  *   `asn1IntegerToHex`, `asn1IntegerToDecimal`, `asn1IntegerFromHex`.
*   **Fluent Builders**:
    *   `X509CertificateBuilder`: Create Self-Signed or CA-Signed certificates.
    *   `X509RequestBuilder`: Generate CSRs (Certificate Signing Requests).
  *   `X509CrlBuilder`: Generate and sign CRLs directly via FFI.
*   **Formats**: Full support for PEM and DER.

### Cryptography & Signing (CMS/PAdES)
*   **Key Management**: Generate and load RSA/EVP keys (PEM/DER/Encrypted PEM).
*   **Modern/PQC Key Generation**:
    *   EdDSA/XDH: `generateEd25519`, `generateEd448`, `generateX25519`, `generateX448`.
    *   ML-DSA: `generateMlDsa44`, `generateMlDsa65`, `generateMlDsa87`.
    *   Generic provider keygen: `generateKeyByName(...)`.
*   **Symmetric Ciphers**:
  *   AES-128/256 (CBC and GCM).
  *   ChaCha20 and ChaCha20-Poly1305.
  *   Rijndael aliases (mapped to AES-128/256 CBC and GCM).
  *   PKCS#7 helpers: `pkcs7Pad`, `pkcs7Unpad`, `aesCbcPkcs7Encrypt`, `aesCbcPkcs7Decrypt`.
*   **CMS/PKCS#7**:
    *   **Detached Signatures**: Critical for PAdES/CAdES standards.
    *   **External Digest Signing**: Support for signing pre-calculated hashes (e.g., for Hardware Security Modules or remote signing flows).
    *   **Verification**: Verify CMS signatures against Trusted Root stores.
*   **One-shot Signatures**:
    *   `signOneShot` / `verifyOneShot`.
    *   ML-DSA helpers: `signMlDsa` / `verifyMlDsa`.
*   **JSON Web Keys (RFC 7517)**: `loadPrivateKeyJwk`, `loadPublicKeyJwk` and
    `EvpPkey.toPublicJwk()` — sign OIDC tokens with the identity provider's JWK
    without converting it to PEM by hand. See [OIDC signing keys](#14-oidc-signing-keys-jwk).
*   **Digests**:
    *   One-shot: `digest(alg, bytes)`, `digestHex(alg, bytes)`, `hmac`.
    *   Incremental/streaming: `startDigest` (an `EvpDigest` you feed with
        `add`/`addStream`), plus `digestStream` and `digestFile` for input that
        does not fit in memory. See [Isolates and concurrency](#isolates-and-concurrency)
        before using these from worker isolates.

### Secure Networking (TLS & DTLS)
*   **Async TLS**: `SecureSocketOpenSslAsync` (API compatible with `dart:io` Socket).
*   **Sync TLS**: `SecureSocketOpenSslSync` (Blocking API, useful for tunnels/proxies).
*   **DTLS 1.2+**: Full support for `DtlsClient` and `DtlsServer` over UDP.

### CRL & OCSP (New)
*   `X509Crl` and `X509CrlBuilder`: Generate and sign CRLs without invoking the OpenSSL executable.
*   `OcspResponseBuilder` and `OcspMixin`: Build DER OCSP responses via FFI.
*   `PkiMixin` cache helpers: `getCachedCrl`/`putCachedCrl` and `getCachedOcsp`/`putCachedOcsp` (TTL-based).

### Issuer Matching & Truststore Performance
*   **Issuer Matching Helpers**:
  *   `extractAkiSki`, `issuerSerialKey`, `certMatchesIssuer`, `prefilterIssuerCandidates`.
  *   Follows secure behavior: binary hints only, no CN/text decision, fallback to full set on ambiguity.
*   **Truststore / Parse Caches**:
  *   `getOrCreateStore(storeKey, rootsDer)` for `X509_STORE` pooling.
  *   `getOrCreateParsedX509(der)` for parsed `X509*` cache by DER fingerprint.
  *   `fingerprintSha256(...)` for stable cache keys.
*   **PEM/DER chain utilities**:
  *   `loadCertificatesFromPemChain`, `convertPemChainToDerList`.
  *   `convertCertificatePemToDer`, `convertCertificateDerToPem`.

### Legacy PKCS#12 (RC2/RC4) on OpenSSL 3.x
*   `ProviderMixin`: `loadLegacyProvider()`, `loadProvider(name)`, `isProviderAvailable(name)`, `setProviderSearchPath(dir)`.
*   `parsePkcs12(..., legacy: true)` and `autoLegacy: true` (detects, loads and, when the module is missing, uses the pure Dart decoder).
*   `pkcs12LegacyAlgorithms(der)` / `pkcs12NeedsLegacyProvider(der)`: identify the algorithm by OID without opening the file.
*   `decodePkcs12Pure(...)` / `parsePkcs12Pure(...)`: 100% Dart PKCS#12, no FFI and no provider.

### X.509 chain verification (New)
*   `verifyChain(...)` on top of `X509_verify_cert`, with CRLs, verification time and partial chains.
*   `VerificationResult`: OpenSSL error code, message, depth, failing certificate and the chain that was built.
*   `verifyCertificateSignature(cert, issuer)`.

### Time-stamping (RFC 3161) (New)
*   `buildTimestampRequest` / `createTimestampResponse` / `verifyTimestamp`: request, issue and verify tokens.
*   Runs an internal TSA with a caller-supplied serial, policy and accuracy; verification covers signature, imprint, nonce, policy and chain.

### Argon2 (RFC 9106)
*   `argon2HashPassword` / `argon2VerifyPassword` with PHC strings, and `argon2Derive` for raw key derivation.
*   Native backend through OpenSSL's `EVP_KDF` (3.2+) with a pure Dart fallback; `hasNativeArgon2` tells which is in use.

### WebAuthn / passkeys
*   `sign`/`verify` route Ed25519, Ed448 and ML-DSA keys to the one-shot API automatically.
*   `loadPublicKeyDer` / `loadPublicKeyBytes` for SubjectPublicKeyInfo coming from COSE keys.

### ICP-Brasil
*   `IcpBrasilParser`: CPF/CNPJ using the official DOC-ICP-04 offsets, with check-digit validation.
*   Reads the rest of the positional block (birth date, NIS, ID card) and every ICP-Brasil `otherName` OID.
*   `maskCpf` / `maskCnpj` for log lines, and an `IcpBrasilInfo.toString()` that never prints a document number.

### TLS (Recommended suites)
*   Recommended TLS 1.2 cipher suite list and TLS 1.3 ciphersuite list (with TLS 1.3 IDs).

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

### Coverage (CI + local)
*   **CI**: The workflow `.github/workflows/dart.yml` runs `dart test --coverage=coverage`, converts to `coverage/lcov.info`, uploads it as artifact, and sends it to Codecov.
*   **Local**:

```bash
dart test --coverage=coverage
dart pub global activate coverage
format_coverage --lcov --in=coverage --out=coverage/lcov.info --report-on=lib --packages=.dart_tool/package_config.json
```

*   To show the badge in GitHub, keep the Codecov badge above and configure `CODECOV_TOKEN` in repository secrets (for private repos; public repos may not require token).

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

### 6. Serial Number APIs (ASN.1 / BN)

```dart
import 'package:openssl_bindings/openssl.dart';

final cert = openssl.loadCertificatePem(pem);

final serialBytes = openssl.x509GetSerialBytes(cert.handle);
final serialHex = openssl.x509GetSerialHex(cert.handle); // e.g. 0x01ab...
final serialDec = openssl.x509GetSerialDecimal(cert.handle);

print(serialBytes.length);
print(serialHex);
print(serialDec);
```

### 7. Legacy PKCS#12 (40-bit RC2)

```dart
final openssl = OpenSSL();
final der = File('certificate.p12').readAsBytesSync();

// Diagnosis without opening the file
if (openssl.pkcs12NeedsLegacyProvider(der)) {
  print(openssl.pkcs12LegacyAlgorithms(der)); // [pbeWithSHA1And40BitRC2-CBC]
}

// Recommended: sorts itself out (legacy provider or pure Dart decoder)
final bundle = openssl.parsePkcs12(der, password: pass, autoLegacy: true);

// Explicit control
openssl.loadLegacyProvider();
final withProvider = openssl.parsePkcs12(der, password: pass, legacy: true);

// 100% Dart, no FFI and no legacy module installed
final pure = decodePkcs12Pure(der, password: pass);
print(pure.certificatePem);
print(pure.privateKeyPem);
```

### 8. X.509 chain verification

```dart
final result = openssl.verifyChain(
  certificate: receivedCertificate,
  anchors: [rootCa],
  intermediates: [intermediateCa],
  crls: [caCrl],
  checkRevocation: true,
  verificationTime: signatureDate, // validate as of signing time
);

if (!result.valid) {
  print('${result.message} (code ${result.errorCode}, depth ${result.depth})');
  print('failed at: ${result.failingCertificate}');
}
result.dispose();
```

### 9. Argon2 password hashing

```dart
final openssl = OpenSSL();

// Uses OpenSSL's native Argon2 when the loaded libcrypto is 3.2+,
// and the vendored pure Dart implementation otherwise.
final phc = openssl.argon2HashPassword('user-password');
// $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>

final ok = openssl.argon2VerifyPassword(phc, 'user-password');

// Raw derivation, for key material rather than password storage
final key = openssl.argon2DeriveFromString(
  'passphrase',
  openssl.randomBytes(16),
  options: const Argon2Options(memoryKib: 65536, iterations: 3, length: 32),
);
```

### 10. WebAuthn / passkey keys

```dart
// A COSE public key re-encoded as SubjectPublicKeyInfo
final publicKey = openssl.loadPublicKeyDer(spkiDer);

// ES256 (P-256), EdDSA (Ed25519) and RS256 all go through the same call:
// Ed25519 rejects an external digest, so sign/verify switch to the one-shot
// API on their own.
final valid = openssl.verify(publicKey, signedData, signature);
```

### 11. Time-stamping (RFC 3161)

```dart
// Client: ask a TSA to stamp the hash of a signature
final request = openssl.buildTimestampRequest(hash: signatureHash);
final answer = await postToTsa(request.der); // application/timestamp-query

final check = openssl.verifyTimestamp(
  responseDer: answer,
  hash: signatureHash,
  nonce: request.nonce, // matching it is what rules out a replay
  anchors: [tsaRootCa],
);
print(check.token?.genTime);

// Internal TSA: sign with a certificate carrying
// extendedKeyUsage = critical, timeStamping
final response = openssl.createTimestampResponse(
  requestDer: incomingRequest,
  signerCertificate: tsaCertificate,
  signerKey: tsaKey,
  defaultPolicyOid: '1.3.6.1.4.1.99999.1.1',
  serialNumber: nextSerialFromTheDatabase, // must be unique per TSA
);

// Later, with only the archived token and no request left
final archived = openssl.verifyTimestamp(
  tokenDer: token.der,
  hash: signatureHash,
  anchors: [tsaRootCa],
);
```

### 12. Issuer pre-filter + secure fallback

```dart
final childInfo = openssl.extractAkiSki(childCertPtr);

final candidates = openssl.prefilterIssuerCandidates<Pointer<X509>>(
  candidates: allIssuerCandidates,
  matches: (issuerPtr) {
    final issuerInfo = openssl.extractAkiSki(issuerPtr);
    return openssl.certMatchesIssuer(
      childAki: childInfo.aki,
      issuerSki: issuerInfo.ski,
      issuerSerialBytes: issuerInfo.serialBytes,
      issuerNameHash: issuerInfo.issuerNameHash,
    );
  },
);

// Always run full certificate chain validation afterwards.
```

### 13. Digests: one-shot and streaming

For data already in memory, one call does it:

```dart
final bytes = utf8.encode('hello') as Uint8List;

final digest = openssl.digest('sha256', bytes);      // Uint8List
final hex    = openssl.digestHex('sha256', bytes);   // lowercase hex
final mac    = openssl.hmac('sha256', key, bytes);
```

For data that does not fit in memory — an upload, an attachment, a socket —
`startDigest` returns an `EvpDigest` you feed in pieces. Native memory stays
bounded by its scratch buffer (64 KiB by default) no matter how large the input
or the individual chunks are:

```dart
final digest = openssl.startDigest('sha256');
try {
  await digest.addStream(File('attachment.pdf').openRead());
  print('${digest.length} bytes -> ${digest.finishHex()}');
} finally {
  digest.dispose();   // idempotent; already done by a successful finish()
}
```

`length` reports how many bytes were fed, so code that needs the size of what it
hashed does not have to `stat` the input separately — which would also leave a
window for it to change between the two reads.

When only the digest matters, two shortcuts skip the object entirely:

```dart
final fromStream = await openssl.digestStream('sha256', request.read());
final fromFile   = await openssl.digestFile('sha256', File('report.pdf'));
```

Always `dispose()` an `EvpDigest` from a `finally`: it is what releases the
native context when the input stream fails halfway. A digest that is garbage
collected without it is still released by a `NativeFinalizer`, but that is a
safety net, not a strategy.

#### Replacing `package:crypto`

The native implementation is substantially faster than a pure-Dart one on large
inputs, which is the usual reason to switch. The mapping is mechanical:

| `package:crypto` | This package |
| --- | --- |
| `sha256.convert(x).bytes` | `openssl.digest('sha256', x)` |
| `sha256.convert(x).toString()` | `openssl.digestHex('sha256', x)` |
| `md5.convert(x).toString()` | `openssl.digestHex('md5', x)` |
| `Hmac(sha256, key).convert(x).bytes` | `openssl.hmac('sha256', key, x)` |
| `sha256.startChunkedConversion(AccumulatorSink<Digest>())` | `openssl.startDigest('sha256')` |
| `Digest` in a signature | `Uint8List`, or `String` for hex |

Two things worth knowing before converting everything:

*   **Small inputs in short-lived isolates may get slower.** Constructing an
    `OpenSSL` loads libcrypto/libssl, and a one-off `Isolate.run` job pays that
    on every spawn. Hashing a few kilobytes — a PDF byte range, say — can cost
    less in pure Dart than the load costs. Measure that case rather than
    assuming; the native win is on large inputs and on long-lived isolates that
    amortise the load.
*   **`package:crypto_keys` is a different package.** It covers JWS/JWT key
    handling, not digests, and nothing here replaces it.

### 14. OIDC signing keys (JWK)

An OpenID Connect identity provider usually keeps its signing key as a JSON Web
Key, not as PEM. These load one directly, so signing a token does not require
converting the key by hand:

```dart
final jwk = jsonDecode(File('idp-private.jwk').readAsStringSync())
    as Map<String, Object?>;

final signingKey = openssl.loadPrivateKeyJwk(jwk);

// RS256 signing input: base64url(header) + '.' + base64url(payload)
final signature = openssl.sign(signingKey, signingInput);
```

The CRT parameters (`dp`, `dq`, `qi`) are optional in a JWK — `package:jose`
omits them when it generates a key — so they are derived from `d`, `p` and `q`
when absent. `loadPublicKeyJwk` accepts a private JWK too, ignoring the private
parameters, so one key file yields both halves.

For a `jwks_uri` endpoint, export the public half back out:

```dart
final jwks = {
  'keys': [signingKey.toPublicJwk(keyId: kid, algorithm: 'RS256', use: 'sig')],
};
```

Only RSA keys are handled; EC and OKP JWKs throw rather than silently producing
a key that cannot verify anything. Load those from PEM or DER instead.

**Interoperability.** RS256 is deterministic, and OpenSSL produces
byte-identical signatures to `package:jose` for the same key and input — tokens
signed here verify there and vice versa, and an exported JWK loads back into a
`jose` key store unchanged. One cosmetic difference: values are emitted without
base64url padding, as RFC 7515 §2 requires, while `jose` pads its own; both
decode to the same bytes and each accepts the other's form.

**Why it is worth doing.** Measured on RSA-2048, one process, warm:

| Operation | `package:jose` (pure Dart) | This package | |
| --- | --- | --- | --- |
| RS256 sign (full compact JWS) | 3.106 ms | 0.756 ms | **4.1× faster** |
| RS256 verify | 0.702 ms | 0.090 ms | **7.8× faster** |
| Load a key from a JWK | — | 0.101 ms | once per process |

Verification is the one that compounds: it runs on every authenticated request,
not once per login. Do measure your own case before switching — if a request
spends milliseconds in the database, 0.6 ms of token verification is not what is
slow.

## Isolates and concurrency

**An `OpenSSL` instance cannot cross an isolate boundary**, and neither can
anything holding a handle from it — `EvpPkey`, `X509Certificate`, `EvpDigest`.
The instance owns a `DynamicLibrary` and raw pointers, which are not sendable
and are only valid in the isolate that created them. Sending one fails with:

```text
Invalid argument(s): Illegal argument in isolate message: (object is a DynamicLibrary)
```

Inside a single isolate, one instance is safe to share across concurrent
operations: each call allocates its own context and frees it before returning,
and the instance itself only holds the loaded library's function pointers. So
the rule is **one instance per isolate**, built once and reused — not one per
call, and not one shared across isolates:

```dart
// In a long-lived worker isolate:
final openssl = OpenSSL();            // once, for the isolate's lifetime
await for (final job in inbox) {      // shared by every job it serves
  reply.send(openssl.digestHex('sha256', job.data));
}
```

The trap is doing it by accident. A closure passed to `Isolate.run` carries its
entire captured context — including parent scopes it never reads — so writing
the closure anywhere an `OpenSSL` variable happens to be in scope drags the
instance along and the spawn fails at runtime:

```dart
// Wrong: `openssl` is in the enclosing scope, so it is captured and sent,
// even though the closure never mentions it.
final openssl = OpenSSL();
await Isolate.run(() => OpenSSL().digestHex('sha256', data)); // throws

// Right: a top-level function, with nothing but sendable data in scope.
Future<String> hashInIsolate(Uint8List data) =>
    Isolate.run(() => OpenSSL().digestHex('sha256', data));
```

`test/concurrency/multi_isolate_stress_test.dart` pins all of this against a
workload shaped like a production backend: long-lived worker isolates serving a
mixed load (digests, streamed file digests, HMAC, AES, RSA sign/verify,
certificate building) while short-lived `Isolate.run` jobs are spawned and
discarded underneath them. It asserts that results from every isolate match the
main isolate's, that an OpenSSL-level failure in one isolate leaves the others
working, that no isolate dies with an uncaught error, and that the process
resident-set floor does not climb across rounds. Turn it up with
`ISOLATE_STRESS_WORKERS`, `ISOLATE_STRESS_JOBS`, `ISOLATE_STRESS_ROUNDS` and
`ISOLATE_STRESS_MAX_MB`:

```sh
ISOLATE_STRESS_WORKERS=8 ISOLATE_STRESS_JOBS=40 ISOLATE_STRESS_ROUNDS=12 \
  dart test test/concurrency/multi_isolate_stress_test.dart
```
