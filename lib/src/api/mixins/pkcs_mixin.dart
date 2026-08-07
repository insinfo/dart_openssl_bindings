import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../openssl.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../crypto/evp_pkey.dart';
import '../../x509/x509_certificate.dart';
import '../../pkcs/pkcs12_bundle.dart';
import 'provider_mixin.dart';
import '../../pkcs/pure/pkcs12_pure.dart';

/// Mixin for PKCS#7 (.p7b) and PKCS#12 (.pfx/.p12) helpers.
mixin PkcsMixin on OpenSslContext {
  /// Extracts certificates from a PKCS#7/CMS DER payload (.p7b).
  List<X509Certificate> loadCertificatesFromPkcs7Der(Uint8List der) {
    final cms = _d2iCms(der);
    try {
      final stack = bindings.CMS_get1_certs(cms);
      if (stack == nullptr) return const [];
      return _x509StackToList(
        stack.cast(),
        duplicateCerts: true,
        freeStackAndCerts: true,
      );
    } finally {
      bindings.CMS_ContentInfo_free(cms);
    }
  }

  /// Extracts certificates from a PKCS#7/CMS PEM string (.p7b).
  List<X509Certificate> loadCertificatesFromPkcs7Pem(String pem) {
    return loadCertificatesFromPkcs7Der(_pemToDer(pem));
  }

  /// Extracts certificates from PKCS#7 bytes (auto-detect PEM vs DER).
  List<X509Certificate> loadCertificatesFromPkcs7Bytes(Uint8List bytes) {
    if (_looksLikePem(bytes)) {
      final pem = String.fromCharCodes(bytes);
      return loadCertificatesFromPkcs7Pem(pem);
    }
    return loadCertificatesFromPkcs7Der(bytes);
  }

  /// Parses PKCS#12/PFX (DER) and returns key, certificate and chain.
  ///
  /// [legacy] loads the OpenSSL 3.x `legacy` provider before calling
  /// `PKCS12_parse`. It is needed for files encrypted with algorithms that
  /// left the default provider in 3.0, typically
  /// `pbeWithSHA1And40BitRC2-CBC` and `pbeWithSHA1And128BitRC4`. Without the
  /// provider, OpenSSL fails with a generic error that looks like a wrong
  /// password.
  ///
  /// Use [pkcs12NeedsLegacyProvider] to decide beforehand, or just pass
  /// `legacy: true` — loading the provider is idempotent and keeps the
  /// `default` provider active.
  ///
  /// [autoLegacy] handles everything on its own: it detects the algorithm by
  /// OID, loads the provider when the file needs it and, if the `legacy`
  /// module is not installed, opens the file with the pure Dart decoder
  /// ([parsePkcs12Pure]). This is the option to reach for in application code.
  Pkcs12Bundle parsePkcs12(
    Uint8List der, {
    String password = '',
    bool legacy = false,
    bool autoLegacy = false,
  }) {
    final arena = Arena();
    Pointer<PKCS12> p12 = nullptr;

    if (legacy) {
      _providerMixin.loadLegacyProvider();
    } else if (autoLegacy && pkcs12NeedsLegacyProvider(der)) {
      // With no `legacy` module installed, fall back to the pure Dart decoder
      // instead of failing: the resulting bundle is the same.
      final provider =
          _providerMixin.loadLegacyProvider(required: false);
      if (provider == null) {
        return parsePkcs12Pure(der, password: password);
      }
    }

    try {
      final inPtr = arena<UnsignedChar>(der.length);
      inPtr.cast<Uint8>().asTypedList(der.length).setAll(0, der);
      final inOutPtr = arena<Pointer<UnsignedChar>>();
      inOutPtr.value = inPtr;

      p12 = bindings.d2i_PKCS12(nullptr, inOutPtr, der.length);
      if (p12 == nullptr) {
        throw OpenSslException('d2i_PKCS12 failed');
      }

      final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
      final certPtr = calloc<Pointer<X509>>();
      final caPtr = calloc<Pointer<stack_st_X509>>();
      Pointer<Char> passPtr = nullptr;

      if (password.isNotEmpty) {
        passPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
      }

      try {
        final result = bindings.PKCS12_parse(
          p12,
          passPtr,
          pkeyPtr,
          certPtr,
          caPtr,
        );
        if (result != 1) {
          throw _pkcs12ParseException(der, usedLegacy: legacy);
        }

        final pkey = EvpPkey(pkeyPtr.value, this as OpenSSL);
        final cert = X509Certificate(certPtr.value, this as OpenSSL);
        final caStack = caPtr.value;
        final ca = caStack == nullptr
            ? const <X509Certificate>[]
            : _x509StackToList(
          caStack.cast<OPENSSL_STACK>(),
                duplicateCerts: false,
                freeStackOnly: true,
              );

        return Pkcs12Bundle(
          privateKey: pkey,
          certificate: cert,
          caCertificates: ca,
        );
      } finally {
        calloc.free(pkeyPtr);
        calloc.free(certPtr);
        calloc.free(caPtr);
        if (passPtr != nullptr) {
          calloc.free(passPtr);
        }
      }
    } finally {
      if (p12 != nullptr) {
        bindings.PKCS12_free(p12);
      }
      arena.releaseAll();
    }
  }

  /// Opens a PKCS#12/PFX with the **pure Dart** decoder: no OpenSSL in the
  /// decryption path and no need for the `legacy` provider.
  ///
  /// The resulting key and certificates are loaded into OpenSSL afterwards, so
  /// the return value is the same [Pkcs12Bundle] as [parsePkcs12]. Useful where
  /// the `legacy` module is not installed (containers, slim images) and the
  /// file uses RC2/RC4 — see [decodePkcs12Pure].
  Pkcs12Bundle parsePkcs12Pure(Uint8List der, {String password = ''}) {
    final pure = decodePkcs12Pure(der, password: password);
    final openssl = this as OpenSSL;

    return Pkcs12Bundle(
      privateKey: openssl.loadPrivateKeyPem(pure.privateKeyPem),
      certificate: openssl.loadCertificatePem(pure.certificatePem),
      caCertificates:
          pure.chainPem.map(openssl.loadCertificatePem).toList(growable: false),
    );
  }

  ProviderMixin get _providerMixin {
    final Object context = this;
    if (context is ProviderMixin) return context;
    throw OpenSslException(
      'Loading the legacy provider requires an instance with ProviderMixin '
      '(the OpenSSL class already mixes it in)',
    );
  }

  /// Creates a PKCS#12/PFX bundle (DER) with key + certificate (+ optional chain).
  Uint8List createPkcs12({
    required EvpPkey privateKey,
    required X509Certificate certificate,
    List<X509Certificate> caCertificates = const [],
    String? password,
    String? friendlyName,
    int iterations = 2048,
    int macIterations = 2048,
  }) {
    Pointer<stack_st_X509> caStack = nullptr;
    Pointer<Char> passPtr = nullptr;
    Pointer<Char> namePtr = nullptr;

    try {
      if (password != null && password.isNotEmpty) {
        passPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
      }
      if (friendlyName != null && friendlyName.isNotEmpty) {
        namePtr = friendlyName.toNativeUtf8(allocator: calloc).cast<Char>();
      }

      if (caCertificates.isNotEmpty) {
        caStack = _createX509Stack(caCertificates);
      }

      final pkcs12 = bindings.PKCS12_create(
        passPtr,
        namePtr,
        privateKey.handle,
        certificate.handle,
        caStack,
        0,
        0,
        iterations,
        macIterations,
        0,
      );

      if (pkcs12 == nullptr) {
        throw OpenSslException('PKCS12_create failed');
      }

      try {
        return _i2dPkcs12(pkcs12);
      } finally {
        bindings.PKCS12_free(pkcs12);
      }
    } finally {
      if (caStack != nullptr) {
        _freeX509StackAndCerts(caStack.cast<OPENSSL_STACK>());
      }
      if (passPtr != nullptr) {
        calloc.free(passPtr);
      }
      if (namePtr != nullptr) {
        calloc.free(namePtr);
      }
    }
  }

  /// Legacy algorithms (outside the OpenSSL 3.x default provider) present in
  /// the [der] PKCS#12 file, by readable name. Empty when the file only uses
  /// algorithms the `default` provider supports.
  ///
  /// The scan runs over the OIDs encoded in the DER, so it works even when the
  /// file cannot be opened for lack of the provider.
  List<String> pkcs12LegacyAlgorithms(Uint8List der) {
    final encontrados = <String>[];
    for (final entry in _legacyOids.entries) {
      if (_containsSequence(der, entry.key)) {
        encontrados.add(entry.value);
      }
    }
    return encontrados;
  }

  /// Whether the [der] PKCS#12 file needs the `legacy` provider to be opened.
  ///
  /// Equivalent to `pkcs12LegacyAlgorithms(der).isNotEmpty`.
  bool pkcs12NeedsLegacyProvider(Uint8List der) =>
      pkcs12LegacyAlgorithms(der).isNotEmpty;

  OpenSslException _pkcs12ParseException(
    Uint8List der, {
    required bool usedLegacy,
  }) {
    final code = bindings.ERR_get_error();
    OpenSslException.clearError(bindings);

    final legacyAlgorithms = pkcs12LegacyAlgorithms(der);
    if (legacyAlgorithms.isEmpty) {
      return OpenSslException(
        'PKCS12_parse failed (wrong password or invalid file)',
        code,
        'PKCS12_parse',
      );
    }

    if (usedLegacy) {
      return OpenSslException(
        'PKCS12_parse failed. The file uses '
        '${legacyAlgorithms.join(', ')} and the "legacy" provider was loaded, '
        'so the likely cause is a wrong password or a corrupted file.',
        code,
        'PKCS12_parse',
      );
    }

    return OpenSslException(
      'PKCS12_parse failed. The file uses ${legacyAlgorithms.join(', ')}, '
      'which OpenSSL 3.x moved from the "default" provider to "legacy". This '
      'is usually NOT a wrong password: call parsePkcs12(..., legacy: true) '
      'or loadLegacyProvider() first.',
      code,
      'PKCS12_parse',
    );
  }

  /// OIDs (in DER, without the OBJECT IDENTIFIER header) of algorithms that
  /// left the OpenSSL 3.x default provider, mapped to the name used in error
  /// messages.
  ///
  /// Note that `pbeWithSHA1And3-KeyTripleDES-CBC` (`...1.12.1.3`) and the
  /// 2-key variant (`.4`) are still in the default provider, hence absent.
  static const Map<List<int>, String> _legacyOids = {
    // 1.2.840.113549.1.12.1.1 - pbeWithSHA1And128BitRC4
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x01]:
        'pbeWithSHA1And128BitRC4',
    // 1.2.840.113549.1.12.1.2 - pbeWithSHA1And40BitRC4
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x02]:
        'pbeWithSHA1And40BitRC4',
    // 1.2.840.113549.1.12.1.5 - pbeWithSHA1And128BitRC2-CBC
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05]:
        'pbeWithSHA1And128BitRC2-CBC',
    // 1.2.840.113549.1.12.1.6 - pbeWithSHA1And40BitRC2-CBC
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06]:
        'pbeWithSHA1And40BitRC2-CBC',
    // 1.2.840.113549.3.2 - rc2-cbc
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02]: 'RC2-CBC',
    // 1.2.840.113549.3.4 - rc4
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x04]: 'RC4',
  };

  static bool _containsSequence(Uint8List haystack, List<int> needle) {
    if (needle.isEmpty || haystack.length < needle.length) return false;
    final limite = haystack.length - needle.length;
    for (var i = 0; i <= limite; i++) {
      var igual = true;
      for (var j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          igual = false;
          break;
        }
      }
      if (igual) return true;
    }
    return false;
  }

  Pointer<CMS_ContentInfo> _d2iCms(Uint8List der) {
    final arena = Arena();
    try {
      final inPtr = arena<UnsignedChar>(der.length);
      inPtr.cast<Uint8>().asTypedList(der.length).setAll(0, der);
      final inOutPtr = arena<Pointer<UnsignedChar>>();
      inOutPtr.value = inPtr;

      final cms = bindings.d2i_CMS_ContentInfo(nullptr, inOutPtr, der.length);
      if (cms == nullptr) {
        throw OpenSslException('d2i_CMS_ContentInfo failed');
      }
      return cms;
    } finally {
      arena.releaseAll();
    }
  }

  Uint8List _i2dPkcs12(Pointer<PKCS12> p12) {
    final len = bindings.i2d_PKCS12(p12, nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_PKCS12 length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    final written = bindings.i2d_PKCS12(p12, out);
    calloc.free(out);

    if (written <= 0) {
      calloc.free(buffer);
      throw OpenSslException('i2d_PKCS12 encode failed');
    }

    final bytes = Uint8List.fromList(buffer.asTypedList(written));
    calloc.free(buffer);
    return bytes;
  }

  Pointer<stack_st_X509> _createX509Stack(
    List<X509Certificate> certificates,
  ) {
    final stack = bindings.OPENSSL_sk_new_null();
    if (stack == nullptr) {
      throw OpenSslException('OPENSSL_sk_new_null failed');
    }

    for (final cert in certificates) {
      if (bindings.X509_up_ref(cert.handle) != 1) {
        throw OpenSslException('X509_up_ref failed');
      }
      final pushResult = bindings.OPENSSL_sk_push(
        stack.cast(),
        cert.handle.cast(),
      );
      if (pushResult == 0) {
        throw OpenSslException('OPENSSL_sk_push failed');
      }
    }

    return stack.cast<stack_st_X509>();
  }

  List<X509Certificate> _x509StackToList(
    Pointer<OPENSSL_STACK> stack, {
    required bool duplicateCerts,
    bool freeStackAndCerts = false,
    bool freeStackOnly = false,
  }) {
    final count = bindings.OPENSSL_sk_num(stack.cast());
    final result = <X509Certificate>[];

    for (var i = 0; i < count; i++) {
      final value = bindings.OPENSSL_sk_value(stack.cast(), i);
      if (value == nullptr) continue;

      final certPtr = value.cast<X509>();
      Pointer<X509> handle = certPtr;

      if (duplicateCerts) {
        final dup = bindings.X509_dup(certPtr);
        if (dup == nullptr) continue;
        handle = dup;
      }

      result.add(X509Certificate(handle, this as OpenSSL));
    }

    if (freeStackAndCerts) {
      _freeX509StackAndCerts(stack);
    } else if (freeStackOnly) {
      bindings.OPENSSL_sk_free(stack.cast());
    }

    return result;
  }

  void _freeX509StackAndCerts(Pointer<OPENSSL_STACK> stack) {
    final freePtr = lookup<Void Function(Pointer<X509>)>('X509_free')
        .cast<NativeFunction<Void Function(Pointer<Void>)>>();
    bindings.OPENSSL_sk_pop_free(stack.cast(), freePtr);
  }

  bool _looksLikePem(Uint8List bytes) {
    final text = String.fromCharCodes(bytes);
    return text.contains('-----BEGIN');
  }

  Uint8List _pemToDer(String pem) {
    final lines = pem
        .split(RegExp(r'\r?\n'))
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty && !line.startsWith('-----'))
        .toList();

    if (lines.isEmpty) {
      throw ArgumentError('Invalid PEM content');
    }

    final base64Data = lines.join();
    return Uint8List.fromList(base64Decode(base64Data));
  }
}
