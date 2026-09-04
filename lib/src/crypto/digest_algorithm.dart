/// A message digest algorithm, by the name OpenSSL knows it under.
///
/// The digest and HMAC APIs take the algorithm as a `String`, which is how
/// `EVP_get_digestbyname` wants it — and how a typo becomes a runtime error.
/// This type carries the same string but gives the usual algorithms a name the
/// compiler checks. It *is* a `String` underneath, so it goes wherever the API
/// takes an algorithm name, with no wrapping or conversion:
///
/// ```dart
/// final mac = openSsl.hmac(DigestAlgorithm.sha256, key, data);
/// final hex = openSsl.digestHex(DigestAlgorithm.sha512, bytes);
/// final digest = openSsl.startDigest(DigestAlgorithm.sha3_256);
/// ```
///
/// Algorithms not listed here can still be named by string, or wrapped with
/// [DigestAlgorithm.new] for callers that want the type at their own API
/// boundary: `const DigestAlgorithm('whirlpool')`.
///
/// Everything listed is in OpenSSL 3's default provider, so none of it needs
/// the `legacy` provider loaded. [md5] and [sha1] are here for checksums and
/// interoperability, not for anything that has to resist an attacker.
extension type const DigestAlgorithm(String opensslName) implements String {
  /// MD5, 16 bytes. Broken for collision resistance; checksums only.
  static const md5 = DigestAlgorithm('md5');

  /// SHA-1, 20 bytes. Broken for collision resistance; legacy interop only.
  static const sha1 = DigestAlgorithm('sha1');

  /// SHA-224, 28 bytes.
  static const sha224 = DigestAlgorithm('sha224');

  /// SHA-256, 32 bytes. The default choice.
  static const sha256 = DigestAlgorithm('sha256');

  /// SHA-384, 48 bytes.
  static const sha384 = DigestAlgorithm('sha384');

  /// SHA-512, 64 bytes.
  static const sha512 = DigestAlgorithm('sha512');

  /// SHA-512/224, 28 bytes: SHA-512 truncated, with its own IV.
  static const sha512_224 = DigestAlgorithm('sha512-224');

  /// SHA-512/256, 32 bytes: SHA-512 truncated, with its own IV.
  static const sha512_256 = DigestAlgorithm('sha512-256');

  /// SHA3-224, 28 bytes.
  static const sha3_224 = DigestAlgorithm('sha3-224');

  /// SHA3-256, 32 bytes.
  static const sha3_256 = DigestAlgorithm('sha3-256');

  /// SHA3-384, 48 bytes.
  static const sha3_384 = DigestAlgorithm('sha3-384');

  /// SHA3-512, 64 bytes.
  static const sha3_512 = DigestAlgorithm('sha3-512');

  /// BLAKE2b with a 64-byte digest.
  static const blake2b512 = DigestAlgorithm('blake2b512');

  /// BLAKE2s with a 32-byte digest.
  static const blake2s256 = DigestAlgorithm('blake2s256');

  /// SM3, 32 bytes (Chinese national standard).
  static const sm3 = DigestAlgorithm('sm3');

  /// Every algorithm this type names, for tests and pickers.
  static const List<DigestAlgorithm> values = [
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    blake2b512,
    blake2s256,
    sm3,
  ];
}
