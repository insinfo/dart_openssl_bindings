## 1.2.0

### Argon2: the pure Dart fallback is 4x faster

On a libcrypto older than 3.2 — Debian 12 and Ubuntu 22.04/24.04 ship 3.0 —
`argon2HashPassword` and `argon2VerifyPassword` run the Dart implementation,
and it was 7x slower than the native one. It has been rewritten for the Dart
VM: one flat `Uint64List` for the block memory instead of 65 536 small
objects, the compression function on native 64-bit words instead of pairs of
32-bit halves, the permutation unrolled over locals, and BLAKE2b on `int`
instead of `BigInt`. The output is unchanged (RFC 9106 vectors, and it still
agrees with OpenSSL's Argon2 byte for byte).

| Argon2id | native (OpenSSL 3.6) | Dart, before | Dart, now (JIT) | Dart, now (AOT) |
|---|---:|---:|---:|---:|
| m=64 MiB, t=3, p=1 | 174 ms | 1383 ms | 325 ms | 370 ms |
| m=32 MiB, t=3, p=1 | 87 ms | 683 ms | 163 ms | 182 ms |
| m=19 MiB, t=2, p=1 | 35 ms | 276 ms | 63 ms | 74 ms |

(i5-10500T, 2.3 GHz.) About 2x native is where scalar Dart tops out: the
kernel is 64-bit adds, 32x32-bit multiplies and rotates, none of which
`Int32x4` offers, so there is no SIMD path to take. `script/bench_argon2.dart`
reproduces the table.

One VM quirk worth knowing about, because it is the difference between 60 ms
and 15 s: the JIT sees the two 32-bit operands of `lo32(a) * lo32(b)`, guesses
a Smi multiply, overflows, deoptimises at each of the 32 sites — and past its
budget stops optimising the function at all. The multiply is written as
`((lo32(a) | 2^63) * lo32(b)) << 1`, which is the same value (the shift drops
the extra bit) with a Mint operand the JIT never speculates on. A test pins
the 19 MiB derivation under 3 s so that cannot silently come back.

### Typed digest names

`DigestAlgorithm` names the usual digests — `sha256`, `sha512`, `sha3_256`,
`blake2b512`, `md5`, … — so a typo is a compile error rather than an
`OpenSslException` at runtime. It is an extension type over `String`, so it
goes wherever the API already takes an algorithm name, with nothing to
convert: `hmac(DigestAlgorithm.sha256, key, data)`,
`startDigest(DigestAlgorithm.sha512)`. Any other OpenSSL name still works as
a plain string, or as `const DigestAlgorithm('whirlpool')`.

### Hex in and out

- **`encodeHex`** and **`decodeHex`** are exported. The encoder was already
  what `digestHex` and `finishHex` used; it is now public for serials,
  fingerprints and stored hashes, and the decoder is strict — odd length or a
  non-hex character is a `FormatException`, not a silently wrong byte.
- **`sha256Hex`** and **`hmacHex`** join `digestHex`, so no caller has to
  convert the `Uint8List` by hand.

### `EvpDigest.copy()`

Forks an incremental digest: same algorithm, buffer size, byte count and
internal state, then each side evolves on its own. It is `EVP_MD_CTX_copy_ex`,
and exists for inputs that share a prefix — hash the header once, copy, feed
each nonce — where re-feeding the prefix per attempt is the cost that
dominates. The copy owns its own native resources and is disposed like any
other `EvpDigest`; disposing either side leaves the other intact.

`EVP_MD_CTX_copy_ex` is the one new FFI symbol, added to `ffigen.yaml` and
regenerated.

## 1.1.0

### Incremental digests

Hashing something that does not fit in memory — a multi-hundred-megabyte
attachment, a socket, a request body — previously meant dropping to the raw FFI
layer and driving `EVP_MD_CTX` by hand. `EvpDigest` covers that case:

- **`startDigest(alg, {bufferSize})`** returns an `EvpDigest`: `add` /
  `addStream` to feed it, `finish` / `finishHex` to read the result, `dispose`
  to release. Native memory stays bounded by `bufferSize` (64 KiB by default)
  regardless of the input size or the size of each chunk. `length` reports how
  many bytes were fed, so callers that need the size of what they hashed do not
  have to measure the input separately.
- **`digestStream(alg, stream)`** and **`digestFile(alg, file)`** for the common
  case where only the digest matters.
- **`digestHex(alg, data)`** and **`EvpDigest.finishHex()`** return lowercase
  hexadecimal, matching what `package:crypto`'s `Digest.toString()` produces.

The context is freed by `finish`, by `dispose` (idempotent, safe in a
`finally`), and by a `NativeFinalizer` as a last resort, so an input stream that
fails halfway does not leak.

No new FFI symbols were needed — `EVP_MD_CTX_new/free`,
`EVP_DigestInit_ex/Update/Final_ex` and `EVP_get_digestbyname` were already
generated.

### JSON Web Keys (RFC 7517)

An OpenID Connect provider keeps its signing key as a JWK, and there was no way
to get one into an `EVP_PKEY` short of converting it to PEM by hand — which is
why signing OIDC tokens meant staying on a pure-Dart implementation.

- **`loadPrivateKeyJwk`** / **`loadPublicKeyJwk`** load an RSA JWK directly. The
  CRT parameters (`dp`, `dq`, `qi`) are optional in a JWK — `package:jose` omits
  them when generating a key — so they are derived from `d`, `p` and `q` when
  absent. `loadPublicKeyJwk` accepts a private JWK, ignoring the private half,
  so one key file yields both keys.
- **`EvpPkey.toPublicJwk()`** exports the public half for a `jwks_uri`
  endpoint, with optional `kid`, `alg` and `use`.
- **`loadPrivateKeyDer`** and **`EvpPkey.toPublicKeyDer()`** fill in the DER
  counterparts of the existing PEM entry points.

RS256 signatures are byte-identical to `package:jose`'s for the same key and
input, so tokens interoperate in both directions. Measured on RSA-2048, signing
a compact JWS is ~4× faster and verifying one ~8× faster than the pure-Dart
path. Only RSA is handled; EC and OKP JWKs throw rather than silently producing
a key that cannot verify anything.

No new FFI symbols here either — `d2i_AutoPrivateKey` and `i2d_PUBKEY` were
already generated, and the JWK/DER translation is pure Dart on top of the
existing DER reader.

### Multi-isolate coverage and documentation

`test/concurrency/multi_isolate_stress_test.dart` runs a workload shaped like a
production backend — long-lived worker isolates serving a mixed load (digests,
streamed file digests, HMAC, AES, RSA sign/verify, certificate building) while
short-lived `Isolate.run` jobs are spawned and discarded underneath them, all in
one process. It asserts that every isolate's results match the main isolate's,
that an OpenSSL-level failure stays contained in the isolate that raised it,
that no isolate dies with an uncaught error, and that the process resident-set
floor does not climb across rounds. Scale it with `ISOLATE_STRESS_WORKERS`,
`ISOLATE_STRESS_JOBS`, `ISOLATE_STRESS_ROUNDS` and `ISOLATE_STRESS_MAX_MB`.

Writing it turned up a sharp edge now documented on the `OpenSSL` class and in
the README: an instance cannot cross an isolate boundary, and a closure passed
to `Isolate.run` captures its whole enclosing context — so merely writing that
closure in a scope where an `OpenSSL` variable exists sends the instance along
and the spawn dies with `Illegal argument in isolate message: (object is a
DynamicLibrary)`, even when the closure never mentions it. The rule is one
instance per isolate, and spawns hoisted into a top-level function whose scope
holds only sendable data. A test pins it.


## 1.0.0

### Legacy PKCS#12 (RC2/RC4) - the case that drove this release

`.p12` files issued by several CAs (Tramita.GOV.BR's among them) use
`pbeWithSHA1And40BitRC2-CBC`, which OpenSSL 3.0 removed from the `default`
provider. The symptom was misleading: `PKCS12_parse failed (check password?)`
with the correct password. There are now three routes, from the simplest to the
most explicit:

- **`ProviderMixin`** - the OpenSSL 3.x provider API: `loadProvider`,
  `loadLegacyProvider`, `unloadProvider`, `unloadProviders`,
  `isProviderAvailable`, `setProviderSearchPath`, `providerSearchPath` and
  `loadedProviders`. Loading goes through
  `OSSL_PROVIDER_try_load(..., retain_fallbacks=1)`, so the `default` provider
  stays active. When the module is missing from the `MODULESDIR` compiled into
  libcrypto (common with the Windows installer, which points at a directory
  that does not exist), the search continues through `OPENSSL_MODULES` and the
  usual platform locations.
- **`parsePkcs12(..., legacy: true)`** loads the provider before
  `PKCS12_parse`; **`autoLegacy: true`** detects the algorithm by OID, loads
  the provider when needed and, if the module is missing, falls back to the
  pure Dart decoder.
- **100% Dart PKCS#12 decoder** (`decodePkcs12Pure` / `parsePkcs12Pure`), with
  no FFI and no provider: it implements ASN.1/DER, the PKCS#12 KDF, SHA-1,
  SHA-256, HMAC, PBKDF2, RC2, RC4, DES/3DES and AES-CBC. It supports
  `pbeWithSHA1And{40,128}BitRC{2,4}`, `pbeWithSHA1And{2,3}-KeyTripleDES-CBC`
  and PBES2 (PBKDF2 + AES-CBC/3DES-CBC). Every primitive is checked against the
  vectors of RFC 2268, RFC 2202, RFC 6070, FIPS 46-3 and FIPS 197.

Diagnostics: `pkcs12LegacyAlgorithms(der)` and `pkcs12NeedsLegacyProvider(der)`
identify the algorithm by OID without opening the file, and the `parsePkcs12`
error message no longer blames the password when the algorithm is the problem.

### X.509 chain verification

- `VerificationMixin.verifyChain(...)` on top of `X509_verify_cert`, returning a
  `VerificationResult` with the OpenSSL error code, its message, the depth, the
  certificate that failed and the chain that was built. Options: anchors,
  intermediates, CRLs (`checkRevocation`, `checkRevocationChain`),
  `verificationTime` to validate old signatures, `ignoreValidity`,
  `partialChain` and `maxDepth`.
- `verifyCertificateSignature(cert, issuer)` to check the signature alone.

### Time-stamping (RFC 3161)

- `TimestampMixin`, covering the three sides of RFC 3161:
  - **client**: `buildTimestampRequest` / `buildTimestampRequestForData` build a
    `TimeStampReq` with a random 64-bit nonce by default, checking that the
    imprint length matches the digest;
  - **TSA**: `createTimestampResponse` issues a `TimeStampResp` from a signing
    certificate that carries `extendedKeyUsage = critical, timeStamping`, with
    the policy, the accepted digests, the declared accuracy, the clock
    precision and — through the OpenSSL serial callback — a serial number the
    caller reserves, instead of the constant 1 OpenSSL falls back to;
  - **verification**: `verifyTimestamp` checks the signature, the message
    imprint, the nonce and the policy, and builds a chain up to the given trust
    anchors. It takes either a whole response or a bare archived token; with no
    nonce at hand (the usual case for an archived token) the nonce check is
    skipped and everything else still holds.
- `parseTimestampResponse` / `parseTimestampToken` return `TimestampToken` with
  `genTime`, serial, policy, imprint, nonce, accuracy, ordering and version, and
  `TimestampResponse` with the `PKIStatus`, its text and the failure bits.

### Argon2 (RFC 9106)

- `Argon2Mixin`: `argon2Derive`, `argon2DeriveFromString`,
  `argon2HashPassword` and `argon2VerifyPassword`, with `Argon2Options`
  (variant, iterations, memory, lanes, length, secret, associated data) and PHC
  string encoding/parsing (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
- Two backends behind the same API: OpenSSL's native Argon2 (`EVP_KDF`, from
  OpenSSL 3.2) when available, and a vendored pure Dart implementation
  otherwise - `hasNativeArgon2` reports which one is in play and `backend:`
  forces either. Both are checked against the RFC 9106 vectors for Argon2i,
  Argon2d and Argon2id, and against each other.

### WebAuthn / passkeys

- `sign` and `verify` now route keys that reject an external digest - Ed25519,
  Ed448 and ML-DSA - to `signOneShot`/`verifyOneShot`, instead of failing with
  OpenSSL's opaque `error:1C80007A:Provider routines::invalid digest`.
  `keyRequiresOneShotSignature(key)` exposes the check, and
  `allowOneShotFallback: false` restores the previous behaviour.
- `loadPublicKeyDer(der)` loads a SubjectPublicKeyInfo directly, which is the
  shape a COSE passkey key ends up in; `loadPublicKeyBytes` auto-detects PEM
  versus DER.

### ICP-Brasil

- `IcpBrasilParser`: CPF and CNPJ extraction using the official offsets of the
  DOC-ICP-04 block (`[8, 19)` for the CPF), preferring the Subject DN
  `serialNumber`, with check-digit validation. It also reads the remaining
  fields of the block - birth date, NIS/PIS and ID card - and carries the
  named constants for every ICP-Brasil `otherName` OID.
- `maskCpf` / `maskCnpj` for log lines that must not carry a full document
  number, and an `IcpBrasilInfo.toString()` that never prints one.
- **Behaviour change**: `IcpBrasilInfo.cpf` now carries the 11-digit CPF rather
  than the raw positional block, which moved to `cpfOtherNameRaw`. Code doing
  `cpf.substring(0, 11)` used to get a wrong number (birth date + 3 CPF
  digits). The extraction is positional on purpose: a block can hold more than
  one 11-digit window with valid check digits, and a birth date can start one -
  there is a test for exactly that.
- **Bug fix**: `IcpBrasilInfo.birthDate` was read from OID `2.16.76.1.3.6`,
  which DOC-ICP-04 defines as the INSS registration (CEI), not a date. The
  birth date now comes from the first 8 digits of the natural-person block, and
  the CEI has its own `cei` field.
- New fields on `IcpBrasilInfo`: `nis`, `idCard`, `cei`, `voterRegistration`,
  `companyName`, `responsibleName` and `isLegalEntity`.

### Certificate

- `X509Certificate.publicKey` and `X509Certificate.serialNumberBigInt`.

### FFI

- `ffigen.yaml` extended and bindings regenerated with `openssl/provider.h`
  (`OSSL_PROVIDER_load`, `OSSL_PROVIDER_try_load`, `OSSL_PROVIDER_unload`,
  `OSSL_PROVIDER_available`, `OSSL_PROVIDER_get0_name`,
  `OSSL_PROVIDER_{set_default,get0_default}_search_path`), chain verification
  (`X509_verify_cert`, `X509_STORE_CTX_*`, `X509_VERIFY_PARAM_*`,
  `X509_STORE_add_crl`, the `X509_V_*` constants), `openssl/kdf.h`
  (`EVP_KDF_fetch`, `EVP_KDF_CTX_new`, `EVP_KDF_derive`, ...),
  `OSSL_PARAM_construct_uint*`, `d2i_PUBKEY`, `EVP_PKEY_get_base_id`,
  `OBJ_nid2sn` and `openssl/ts.h` (`TS_REQ_*`, `TS_RESP_*`, `TS_RESP_CTX_*`,
  `TS_VERIFY_CTX_*`, `TS_TST_INFO_*`, the `TS_STATUS_*`/`TS_VFY_*` constants).

### Tests

- `test/provider_legacy_test.dart`, `test/pkcs12_legacy_message_test.dart`,
  `test/pkcs12_pure_test.dart`, `test/chain_verification_test.dart`,
  `test/icp_brasil_parser_test.dart`, `test/argon2_test.dart`,
  `test/webauthn_keys_test.dart` and `test/timestamp_test.dart` (an internal
  TSA issuing, and the verifier rejecting, a replayed or retargeted token),
  with a real `test/fixtures/legacy_rc2_40.p12` fixture (40-bit RC2).

## 0.6.0 

- **OCSP (Client APIs):**
  - Added `OcspClient` with DER request generation and response parsing (`buildRequestDer`, `readResponseStatus`).
  - Added high-level `OcspMixin` helpers: `buildOcspRequest(...)` and `readOcspResponseStatus(...)`.
  - Exported client API in package entrypoint (`lib/openssl.dart`).
- **CRL (Loading + Revocation Check):**
  - Added CRL loading helpers in `X509Mixin`: `loadCrlPem`, `loadCrlDer`, `loadCrlBytes`.
  - Added revocation lookup helpers in `X509Crl`:
    `isSerialRevoked`, `isSerialRevokedDecimal`, `isSerialRevokedHex`,
    `isSerialRevokedBigInt`, and `isCertificateRevoked`.
- **X.509 Extension Reading:**
  - Added certificate getters for endpoint discovery:
    `ocspUrls` (AIA/OCSP) and `crlDistributionPointUrls` (CRL Distribution Points).
- **FFI:**
  - Extended `ffigen.yaml` and regenerated bindings with CRL/OCSP client-side symbols:
    `d2i_X509_CRL`, `PEM_read_bio_X509_CRL`, `X509_CRL_get0_by_serial`,
    `d2i_OCSP_RESPONSE`, `OCSP_response_status`, `OCSP_response_get1_basic`,
    `OCSP_resp_find_status`.
- **PKI Cache Stability:**
  - Updated CRL/OCSP TTL cache expiration logic in `PkiMixin` to use monotonic time (`Stopwatch`) instead of wall-clock (`DateTime.now`) to avoid flaky expiration behavior in short TTL tests.
- **Tests:**
  - Added coverage in `test/crl_ocsp_test.dart` for:
    - OCSP request/response flow without `openssl` executable.
    - CRL parsing + serial revocation checks without CLI.
    - Reading OCSP/CRL URLs from certificate extensions.


## 0.5.0 

- **ASN.1 / Serial Number APIs (no truncation):**
  - Added `x509GetSerialBytes(Pointer<X509>)`.
  - Added `x509GetSerialHex(Pointer<X509>, {bool prefixed = true})`.
  - Added `x509GetSerialDecimal(Pointer<X509>)` via BN decimal conversion.
  - Added safe ASN.1/BN conversion helpers: `asn1IntegerToHex`, `asn1IntegerToDecimal`, `asn1IntegerFromHex`.
- **Issuer Matching + Security Rules:**
  - Added `extractAkiSki`, `issuerSerialKey`, and `certMatchesIssuer` helpers.
  - Added `prefilterIssuerCandidates` with mandatory fallback to full candidate set when empty/ambiguous.
  - Reinforced rule: pre-filter never replaces final chain validation and does not decide by CN/text.
- **PKI Performance Caches:**
  - Added truststore pool/cache by key: `getOrCreateStore(String storeKey, List<Uint8List> rootsDer)`.
  - Added parsed certificate cache by DER fingerprint: `getOrCreateParsedX509(Uint8List der)`.
  - Added shared helper `fingerprintSha256(Uint8List)`.
- **Revocation Cache (optional):**
  - Added TTL caches for CRL/OCSP responses: `getCachedCrl`/`putCachedCrl`, `getCachedOcsp`/`putCachedOcsp`.
- **CI / Coverage:**
  - Updated GitHub Actions workflow to generate `coverage/lcov.info`, upload artifact, and publish to Codecov.
  - Added Codecov badge and local coverage instructions in README.
- **Tests / Organization:**
  - Added focused tests for ASN.1 serial and error branches.
  - Added dedicated PKI cache/matching tests (`test/pki_cache_and_match_test.dart`).
- **Documentation:**
  - README reviewed and expanded with missing APIs (PQC keygen, one-shot/ML-DSA signatures, ASN.1 serial helpers, issuer pre-filter/caches, and PEM/DER chain utilities).

## 0.4.4

- **CRL (Long Serial Support)**:
  - Added BigInt APIs: `addRevokedSerialBigInt`, `addRevokedSerialWithReasonBigInt`, `setCrlNumberBigInt`, `setDeltaCrlIndicatorBigInt`.
  - Updated `addRevokedSerialHex` to support large serials through the BigInt path (removed native `int` limitation).
- **Crypto (Modern/PQC Key Generation)**:
  - Added `generateEd25519`, `generateEd448`.
  - Added `generateX25519`, `generateX448`.
  - Added `generateMlDsa44`, `generateMlDsa65`, `generateMlDsa87`.
  - Added generic `generateKeyByName(...)` helper for provider-based OpenSSL algorithms.
- **Signatures (One-Shot + ML-DSA)**:
  - Added `signOneShot` and `verifyOneShot` with optional `null` digest support (required for ML-DSA/EdDSA flows).
  - Added `MlDsaSignatureOptions` with ML-DSA parameters (`context-string`, `message-encoding`, `test-entropy`, `deterministic`, `mu`).
  - Added high-level helpers: `signMlDsa` and `verifyMlDsa`.
  - Added convenience presets: `MlDsaSignatureOptions.pure`, `.deterministic`, `.mu`.
- **FFI**:
  - Added `EVP_DigestSign`, `EVP_DigestVerify`, and `OSSL_PARAM_construct_int` to bindings (`ffigen.yaml` + regenerated `ffi.dart`).

## 0.4.3 

- **PKI (Mixins)**:
  - Added `PkiMixin` and `PkiBuilderMixin` with serial generation and issuance helpers.
  - Added CA rollover/cross‑cert helpers (`createCrossCertificate`, `createRolloverCrossCertificates`).
- **X.509 Builder**:
  - BigInt serial support, validity setters, DN field helpers, and raw extension support.
- **CRL**:
  - Added CRL Reason per revoked entry, CRL Number, Delta CRL indicator, and Authority Key Identifier support.
- **OCSP**:
  - Added nonce policy handling, responderId by key (flag), and extra responder cert inclusion.
- **ASN.1**:
  - Added negative BigInt two’s‑complement encoding utilities.
- **Tests**:
  - Added/updated tests for PKI helpers, ASN.1, CRL/OCSP, and certificate builder behaviors.

## 0.4.2

- feat(stress): add HTTP signer stress server and test
- add DER export for X509Certificate
- add stress sign server script
- add concurrent stress test for PKCS#7 signing

## 0.4.1

- **PKCS#7 padding**:
  - Added `pkcs7Pad` and `pkcs7Unpad` helpers for high-level padding/unpadding.
- **AES-CBC convenience**:
  - Added `aesCbcPkcs7Encrypt` and `aesCbcPkcs7Decrypt` helpers (AES-128/256).
- **Tests**:
  - Added coverage for PKCS#7 padding and AES-CBC PKCS#7 helpers.

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
