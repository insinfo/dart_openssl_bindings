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
