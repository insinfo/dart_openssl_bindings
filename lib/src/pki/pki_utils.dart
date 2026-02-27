import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../api/openssl_context.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../x509/x509_store.dart';

/// PKI utilities for production-grade operations.
mixin PkiMixin on OpenSslContext {
  final Map<String, X509Store> _storeCache = <String, X509Store>{};
  final Map<String, Pointer<X509>> _parsedCertCache = <String, Pointer<X509>>{};
  final Map<String, _TimedEntry<Uint8List>> _crlCache =
      <String, _TimedEntry<Uint8List>>{};
  final Map<String, _TimedEntry<Uint8List>> _ocspCache =
      <String, _TimedEntry<Uint8List>>{};
  final Stopwatch _ttlClock = Stopwatch()..start();

  /// Generates a cryptographically strong random serial number.
  ///
  /// [bytes] should be between 8 and 20 for production use (RFC 5280).
  BigInt generateSerialNumberBigInt({int bytes = 16}) {
    if (bytes < 8 || bytes > 20) {
      throw RangeError('bytes must be between 8 and 20 for production use');
    }

    final buffer = calloc<UnsignedChar>(bytes);
    try {
      while (true) {
        final ok = bindings.RAND_bytes(buffer, bytes);
        if (ok != 1) {
          throw OpenSslException('RAND_bytes failed');
        }

        final data = buffer.cast<Uint8>().asTypedList(bytes);
        var allZero = true;
        for (final b in data) {
          if (b != 0) {
            allZero = false;
            break;
          }
        }

        if (allZero) {
          continue;
        }

        return _bigIntFromBytes(data);
      }
    } finally {
      calloc.free(buffer);
    }
  }

  BigInt _bigIntFromBytes(Uint8List bytes) {
    var result = BigInt.zero;
    for (final b in bytes) {
      result = (result << 8) | BigInt.from(b);
    }
    return result;
  }

  /// SHA-256 fingerprint in lowercase hexadecimal.
  String fingerprintSha256(Uint8List data) {
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('EVP_MD_CTX_new failed');
    }

    final inputPtr = calloc<UnsignedChar>(data.length);
    final out = calloc<UnsignedChar>(32);
    final outLen = calloc<UnsignedInt>();

    try {
      inputPtr.cast<Uint8>().asTypedList(data.length).setAll(0, data);

      _requireOk(
        bindings.EVP_DigestInit_ex(ctx, bindings.EVP_sha256(), nullptr),
        'EVP_DigestInit_ex failed',
      );
      _requireOk(
        bindings.EVP_DigestUpdate(ctx, inputPtr.cast(), data.length),
        'EVP_DigestUpdate failed',
      );
      _requireOk(
        bindings.EVP_DigestFinal_ex(ctx, out, outLen),
        'EVP_DigestFinal_ex failed',
      );

      final digest = out.cast<Uint8>().asTypedList(outLen.value);
      return _bytesToHex(digest);
    } finally {
      calloc.free(outLen);
      calloc.free(out);
      calloc.free(inputPtr);
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// Parses AKI/SKI + issuer matching material from certificate.
  ({
    Uint8List? aki,
    Uint8List? ski,
    Uint8List serialBytes,
    String issuerNameHash,
  }) extractAkiSki(Pointer<X509> cert) {
    return (
      aki: _extractAki(cert),
      ski: _extractSki(cert),
      serialBytes: _x509SerialBytes(cert),
      issuerNameHash: _subjectNameHash(cert),
    );
  }

  /// Stable key for maps/indexes keyed by issuer name hash + serial bytes.
  String issuerSerialKey({
    required Uint8List issuerSerialBytes,
    required String issuerNameHash,
  }) {
    return '${issuerNameHash.toLowerCase()}:${_bytesToHex(issuerSerialBytes)}';
  }

  /// Pre-filter for issuer candidates based on AKI/SKI + serial/name hints.
  ///
  /// IMPORTANT: this pre-filter never replaces final chain validation.
  /// This helper intentionally does not use CN/text matching.
  bool certMatchesIssuer({
    Uint8List? childAki,
    Uint8List? issuerSki,
    Uint8List? issuerSerialBytes,
    String? issuerNameHash,
  }) {
    if (childAki != null && childAki.isEmpty) return false;
    if (issuerSki != null && issuerSki.isEmpty) return false;
    if (issuerSerialBytes != null && issuerSerialBytes.isEmpty) return false;
    if (issuerNameHash != null && issuerNameHash.trim().isEmpty) return false;

    if (childAki != null &&
        issuerSki != null &&
        !_bytesEqual(childAki, issuerSki)) {
      return false;
    }

    return true;
  }

  /// Applies binary pre-filter and falls back to full set on failure/ambiguity.
  ///
  /// IMPORTANT: this pre-filter never replaces final chain validation.
  List<T> prefilterIssuerCandidates<T>({
    required List<T> candidates,
    required bool Function(T candidate) matches,
  }) {
    if (candidates.length <= 1) {
      return candidates;
    }

    final filtered = <T>[];
    for (final candidate in candidates) {
      if (matches(candidate)) {
        filtered.add(candidate);
      }
    }

    if (filtered.isEmpty || filtered.length > 1) {
      return candidates;
    }
    return filtered;
  }

  /// Returns a cached X509_STORE for a truststore fingerprint key.
  X509Store getOrCreateStore(String storeKey, List<Uint8List> rootsDer) {
    final cached = _storeCache[storeKey];
    if (cached != null) {
      return cached;
    }

    final store = X509Store.create(this);
    for (final rootDer in rootsDer) {
      final certPtr = getOrCreateParsedX509(rootDer);
      try {
        final rc = bindings.X509_STORE_add_cert(store.handle, certPtr);
        if (rc != 1) {
          throw OpenSslException('X509_STORE_add_cert failed for cached root');
        }
      } finally {
        bindings.X509_free(certPtr);
      }
    }

    _storeCache[storeKey] = store;
    return store;
  }

  /// Returns cached parsed certificate pointer keyed by DER fingerprint.
  ///
  /// Caller must release returned pointer with `X509_free`.
  Pointer<X509> getOrCreateParsedX509(Uint8List der) {
    final fp = fingerprintSha256(der);
    final cached = _parsedCertCache[fp];
    if (cached != null) {
      _requireOk(
          bindings.X509_up_ref(cached), 'X509_up_ref failed on cache hit');
      return cached;
    }

    final parsed = _d2iX509(der);
    _parsedCertCache[fp] = parsed;

    _requireOk(
        bindings.X509_up_ref(parsed), 'X509_up_ref failed on cache insert');
    return parsed;
  }

  /// Optional CRL cache with TTL to avoid mass re-fetch.
  Uint8List? getCachedCrl(String key) => _readTtlCache(_crlCache, key);

  /// Optional CRL cache with TTL to avoid mass re-fetch.
  void putCachedCrl(String key, Uint8List value,
      {Duration ttl = const Duration(minutes: 15)}) {
    _writeTtlCache(_crlCache, key, value, ttl);
  }

  /// Optional OCSP cache with TTL to avoid mass re-fetch.
  Uint8List? getCachedOcsp(String key) => _readTtlCache(_ocspCache, key);

  /// Optional OCSP cache with TTL to avoid mass re-fetch.
  void putCachedOcsp(String key, Uint8List value,
      {Duration ttl = const Duration(minutes: 5)}) {
    _writeTtlCache(_ocspCache, key, value, ttl);
  }

  Uint8List? _readTtlCache(
      Map<String, _TimedEntry<Uint8List>> cache, String key) {
    final item = cache[key];
    if (item == null) return null;
    if (_ttlClock.elapsedMicroseconds > item.expiresAtMicros) {
      cache.remove(key);
      return null;
    }
    return Uint8List.fromList(item.value);
  }

  void _writeTtlCache(
    Map<String, _TimedEntry<Uint8List>> cache,
    String key,
    Uint8List value,
    Duration ttl,
  ) {
    final ttlMicros = ttl.inMicroseconds;
    if (ttlMicros <= 0) {
      cache.remove(key);
      return;
    }

    cache[key] = _TimedEntry<Uint8List>(
      Uint8List.fromList(value),
      _ttlClock.elapsedMicroseconds + ttlMicros,
    );
  }

  Pointer<X509> _d2iX509(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final pp = calloc<Pointer<UnsignedChar>>();
    pp.value = dataPtr.cast<UnsignedChar>();

    final cert = bindings.d2i_X509(nullptr, pp, der.length);

    calloc.free(pp);
    calloc.free(dataPtr);

    if (cert == nullptr) {
      throw OpenSslException('d2i_X509 failed');
    }

    return cert;
  }

  Uint8List _x509SerialBytes(Pointer<X509> cert) {
    final serial = bindings.X509_get_serialNumber(cert);
    if (serial == nullptr) {
      throw OpenSslException('X509_get_serialNumber failed');
    }

    final len = bindings.ASN1_STRING_length(serial.cast());
    if (len <= 0) {
      return Uint8List(0);
    }

    final data = bindings.ASN1_STRING_get0_data(serial.cast());
    if (data == nullptr) {
      throw OpenSslException('ASN1_STRING_get0_data failed for serial');
    }

    return Uint8List.fromList(data.cast<Uint8>().asTypedList(len));
  }

  String _subjectNameHash(Pointer<X509> cert) {
    final subject = bindings.X509_get_subject_name(cert);
    if (subject == nullptr) {
      throw OpenSslException('X509_get_subject_name failed');
    }

    final len = bindings.i2d_X509_NAME(subject, nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_X509_NAME length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = bindings.i2d_X509_NAME(subject, out);
      if (written <= 0) {
        throw OpenSslException('i2d_X509_NAME failed');
      }
      return fingerprintSha256(Uint8List.fromList(buffer.asTypedList(written)));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  Uint8List? _extractSki(Pointer<X509> cert) {
    final skiOid = '2.5.29.14'.toNativeUtf8(allocator: calloc);
    final nid = bindings.OBJ_txt2nid(skiOid.cast());
    calloc.free(skiOid);
    if (nid <= 0) {
      return null;
    }

    final ext = bindings.X509_get_ext_d2i(cert, nid, nullptr, nullptr);
    if (ext == nullptr) {
      return null;
    }

    final oct = ext.cast<ASN1_OCTET_STRING>();
    try {
      final len = bindings.ASN1_STRING_length(oct.cast());
      if (len <= 0) return null;
      final data = bindings.ASN1_STRING_get0_data(oct.cast());
      if (data == nullptr) return null;
      return Uint8List.fromList(data.cast<Uint8>().asTypedList(len));
    } finally {
      bindings.ASN1_OCTET_STRING_free(oct);
    }
  }

  Uint8List? _extractAki(Pointer<X509> cert) {
    final akiOid = '2.5.29.35'.toNativeUtf8(allocator: calloc);
    final nid = bindings.OBJ_txt2nid(akiOid.cast());
    calloc.free(akiOid);
    if (nid <= 0) {
      return null;
    }

    final ext = bindings.X509_get_ext_d2i(cert, nid, nullptr, nullptr);
    if (ext == nullptr) {
      return null;
    }

    final aki = ext.cast<AUTHORITY_KEYID>();
    try {
      final keyid = aki.ref.keyid;
      if (keyid == nullptr) {
        return null;
      }

      final len = bindings.ASN1_STRING_length(keyid.cast());
      if (len <= 0) return null;

      final data = bindings.ASN1_STRING_get0_data(keyid.cast());
      if (data == nullptr) return null;

      return Uint8List.fromList(data.cast<Uint8>().asTypedList(len));
    } finally {
      final freeAki = lookup<Void Function(Pointer<AUTHORITY_KEYID>)>(
              'AUTHORITY_KEYID_free')
          .asFunction<void Function(Pointer<AUTHORITY_KEYID>)>();
      freeAki(aki);
    }
  }

  void _requireOk(int rc, String message) {
    if (rc != 1) {
      throw OpenSslException(message);
    }
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (identical(a, b)) return true;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  String _bytesToHex(Uint8List bytes) {
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

final class _TimedEntry<T> {
  final T value;
  final int expiresAtMicros;

  _TimedEntry(this.value, this.expiresAtMicros);
}
