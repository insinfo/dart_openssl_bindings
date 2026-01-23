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
  
