## 0.1.0

- Initial release of OpenSSL bindings for Dart.
- Supports loading OpenSSL symbols dynamically (dlopen).
- Core features implemented:
  - **Crypto**: EVP keys management (RSA key generation, loading PEM/DER).
  - **X.509**: Certificate parsing (Subject, Issuer, Serial, Validity, Version), creating self-signed certificates, signing CSRs.
  - **CMS/PKCS#7**: Detached signing (PAdES compatible) using `signDetached` and `signDetachedDigest`.
  - **TLS/DTLS**:
    - `SecureSocketOpenSSLAsync`: Async TLS client/server socket (dart:io compatible interface).
    - `SecureSocketOpenSSLSync`: Synchronous TLS client/server socket.
    - `DtlsClient` / `DtlsServer`: DTLS 1.2+ support over UDP.
- **Infrastructure**:
  - Memory safe architecture using explicit allocators and finalizers.
  - Flexible library loading: supports custom paths for `libcrypto` and `libssl` via constructor injection or environment variables (`OPENSSL_LIBCRYPTO_PATH`, `OPENSSL_LIBSSL_PATH`).
  - Unit tests covering key generation, certificate building, CMS signing, and SSL/TLS communication.

## 0.2.0

- **HTTP/HTTPS Support**:
  - Introduced `OpenSslHttpClient` and `OpenSslHttpServer` built on OpenSSL BIOs.
  - Added multi-threaded web server example with isolate support (`example/openssl_web_server.dart`).
- **Cryptographic Enhancements**:
  - **Ciphers**: Added AES (CBC, GCM) and generic cipher support (`CipherMixin`).
  - **Hashing & MAC**: implemented Digest, HMAC, and PBKDF2.
  - **Elliptic Curves**: Added EC key generation and ECDSA signing/verification.
  - **PKCS#12**: Added support for loading and parsing PKCS#12 bundles.
- **X.509 & CMS**:
  - **Extensions**: Added builder support for Subject Alternative Names (SAN), Key Usage, Extended Key Usage, and Basic Constraints.
  - **CMS**: Added signature verification capabilities (`verifyDetached`).
  - **ICP-Brasil**: Added helper for ICP-Brasil specific OIDs and extensions.
- **TLS/SSL**:
  - Improved `SecureSocketOpenSslAsync` reliability (fixed hangs, added `recvExact`).
  - Validated parallel SSL session support.
- **Internal**:
  - Refactored native buffer utilities.
  - Updated FFI bindings.
  
## 0.3.0 

- **Breaking change**: Renamed the generated FFI bindings class from `OpenSsl` to `OpenSslFfi` for clarity.
- **Critical fix**: Resolved heap corruption on Linux caused by the `struct tm` size mismatch between Windows and Linux when calling `ASN1_TIME_to_tm`.
  - Windows `struct tm` is 36 bytes; Linux/glibc is larger due to `tm_gmtoff` and `tm_zone`.
  - Added platform-specific `tm` sizing and safe allocation to prevent buffer overflows.
- **Memory safety**:
  - Re-enabled and audited `NativeFinalizer` usage across key wrappers.
  - Fixed missing finalizer attachment in the base `SslObject` helper.
- **CI/Testing**:
  - Added memory-safety regression test for repeated `ASN1_TIME_to_tm` parsing.
  - Linux CI now uses `MALLOC_CHECK_` and `MALLOC_PERTURB_` for earlier detection of heap corruption.

## 0.4.0

- **CRL & OCSP**:
  - Added `X509Crl` and `X509CrlBuilder` to generate and sign CRLs without invoking the OpenSSL executable.
  - Added `OcspResponseBuilder` and `OcspMixin` to build DER OCSP responses directly via FFI.
- **Cipher APIs**:
  - Added AES-128-GCM and AES-128-CBC helpers.
  - Added ChaCha20 and ChaCha20-Poly1305 helpers.
  - Added Rijndael aliases (mapped to AES-128/256 CBC and GCM).
- **TLS constants**:
  - Added recommended TLS 1.2 cipher suite list and TLS 1.3 ciphersuite list + IDs.
- **FFI**:
  - Extended bindings for CRL/OCSP request/response APIs.
- **Tests**:
  - Added coverage for CRL/OCSP generation and new cipher helpers.
- **Docs/cleanup**:
  - Removed an unnecessary import in the tm bug demonstration script.

## 0.4.1

- **PKCS#7 padding**:
  - Added `pkcs7Pad` and `pkcs7Unpad` helpers for high-level padding/unpadding.
- **AES-CBC convenience**:
  - Added `aesCbcPkcs7Encrypt` and `aesCbcPkcs7Decrypt` helpers (AES-128/256).
- **Tests**:
  - Added coverage for PKCS#7 padding and AES-CBC PKCS#7 helpers.

## 0.4.2

- feat(stress): add HTTP signer stress server and test
- add DER export for X509Certificate
- add stress sign server script
- add concurrent stress test for PKCS#7 signing