import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../crypto/evp_pkey.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../infra/ssl_object.dart';
import '../openssl_context.dart';

/// Optional parameters for ML-DSA sign/verify operations.
class MlDsaSignatureOptions {
  /// "context-string" (octet string), max 255 bytes.
  final Uint8List? contextString;

  /// "message-encoding" (integer), used in signing.
  /// 1 = pure ML-DSA encoding (default), 0 = no encoding.
  final int? messageEncoding;

  /// "test-entropy" (octet string), used in signing (must be 32 bytes).
  final Uint8List? testEntropy;

  /// "deterministic" (integer), used in signing.
  final int? deterministic;

  /// "mu" (integer), used in sign/verify.
  final int? mu;

  const MlDsaSignatureOptions({
    this.contextString,
    this.messageEncoding,
    this.testEntropy,
    this.deterministic,
    this.mu,
  });

  /// Preset for "Pure ML-DSA Signature Generation".
  factory MlDsaSignatureOptions.pure({Uint8List? contextString}) {
    return MlDsaSignatureOptions(
      contextString: contextString,
      messageEncoding: 1,
    );
  }

  /// Preset for deterministic signing (test-friendly).
  factory MlDsaSignatureOptions.deterministic({
    Uint8List? contextString,
    int messageEncoding = 1,
  }) {
    return MlDsaSignatureOptions(
      contextString: contextString,
      messageEncoding: messageEncoding,
      deterministic: 1,
    );
  }

  /// Preset for using externally prepared `mu` input.
  factory MlDsaSignatureOptions.mu({
    required int mu,
    Uint8List? contextString,
    int? messageEncoding,
    int? deterministic,
  }) {
    return MlDsaSignatureOptions(
      contextString: contextString,
      messageEncoding: messageEncoding,
      deterministic: deterministic,
      mu: mu,
    );
  }
}

mixin SignatureMixin on OpenSslContext {
  Pointer<EVP_MD> _resolveDigestOrNull(String? algorithm) {
    if (algorithm == null) {
      return nullptr;
    }
    final digestName = algorithm.toNativeUtf8(allocator: calloc);
    try {
      final md = bindings.EVP_get_digestbyname(digestName.cast());
      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $algorithm');
      }
      return md;
    } finally {
      calloc.free(digestName);
    }
  }

  void _applyMlDsaSignatureParams({
    required Pointer<EVP_PKEY_CTX> pkeyCtx,
    required MlDsaSignatureOptions options,
    required bool forSign,
  }) {
    if (pkeyCtx == nullptr) {
      throw OpenSslException('EVP_PKEY_CTX is null');
    }

    final params = <OSSL_PARAM>[];
    final arena = Arena();
    try {
      if (options.contextString != null) {
        final value = options.contextString!;
        if (value.length > 255) {
          throw RangeError('contextString must be <= 255 bytes');
        }
        final key = 'context-string'.toNativeUtf8(allocator: arena);
        final data = arena<UnsignedChar>(value.length);
        data.cast<Uint8>().asTypedList(value.length).setAll(0, value);
        params.add(
          bindings.OSSL_PARAM_construct_octet_string(
            key.cast(),
            data.cast(),
            value.length,
          ),
        );
      }

      if (forSign && options.messageEncoding != null) {
        final key = 'message-encoding'.toNativeUtf8(allocator: arena);
        final v = arena<Int>()..value = options.messageEncoding!;
        params.add(bindings.OSSL_PARAM_construct_int(key.cast(), v));
      }

      if (forSign && options.testEntropy != null) {
        final value = options.testEntropy!;
        if (value.length != 32) {
          throw RangeError('testEntropy must be exactly 32 bytes');
        }
        final key = 'test-entropy'.toNativeUtf8(allocator: arena);
        final data = arena<UnsignedChar>(value.length);
        data.cast<Uint8>().asTypedList(value.length).setAll(0, value);
        params.add(
          bindings.OSSL_PARAM_construct_octet_string(
            key.cast(),
            data.cast(),
            value.length,
          ),
        );
      }

      if (forSign && options.deterministic != null) {
        final key = 'deterministic'.toNativeUtf8(allocator: arena);
        final v = arena<Int>()..value = options.deterministic!;
        params.add(bindings.OSSL_PARAM_construct_int(key.cast(), v));
      }

      if (options.mu != null) {
        final key = 'mu'.toNativeUtf8(allocator: arena);
        final v = arena<Int>()..value = options.mu!;
        params.add(bindings.OSSL_PARAM_construct_int(key.cast(), v));
      }

      if (params.isEmpty) {
        return;
      }

      final p = arena<OSSL_PARAM>(params.length + 1);
      for (var i = 0; i < params.length; i++) {
        p[i] = params[i];
      }
      p[params.length] = bindings.OSSL_PARAM_construct_end();

      if (bindings.EVP_PKEY_CTX_set_params(pkeyCtx, p) <= 0) {
        throw OpenSslException('EVP_PKEY_CTX_set_params failed for ML-DSA');
      }
    } finally {
      arena.releaseAll();
    }
  }

  /// Whether [key] signs the message directly and therefore rejects an
  /// external digest (Ed25519, Ed448 and the ML-DSA family).
  ///
  /// These keys must go through [signOneShot]/[verifyOneShot]; using
  /// [EVP_DigestSignInit] with a digest yields
  /// `error:1C80007A:Provider routines::invalid digest`, which does not say
  /// what is actually wrong.
  bool keyRequiresOneShotSignature(EvpPkey key) {
    final id = bindings.EVP_PKEY_get_base_id(key.handle);
    if (id == NID_ED25519 || id == NID_ED448) return true;

    // ML-DSA ids only exist from OpenSSL 3.5 on; match by name so that older
    // headers do not break the build.
    const mlDsaNames = {'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'};
    return mlDsaNames.contains(_keyTypeName(key));
  }

  /// Algorithm name of [key] as OpenSSL reports it (`ED25519`, `RSA`, ...),
  /// or `null` when it cannot be resolved.
  String? _keyTypeName(EvpPkey key) {
    final id = bindings.EVP_PKEY_get_base_id(key.handle);
    if (id == 0) return null;
    final ptr = bindings.OBJ_nid2sn(id);
    if (ptr == nullptr) return null;
    return ptr.cast<Utf8>().toDartString();
  }

  /// Signs [data] using the private [key].
  ///
  /// [algorithm] defaults to 'SHA256'.
  ///
  /// Keys whose algorithm signs the message directly — Ed25519, Ed448 and
  /// ML-DSA — reject an external digest, so for those this delegates to
  /// [signOneShot] instead of failing with OpenSSL's opaque
  /// `invalid digest` error. Pass [allowOneShotFallback] as `false` to get
  /// that error back.
  Uint8List sign(
    EvpPkey key,
    Uint8List data, {
    String algorithm = 'SHA256',
    bool allowOneShotFallback = true,
  }) {
    if (allowOneShotFallback && keyRequiresOneShotSignature(key)) {
      return signOneShot(key, data);
    }

    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    try {
      final md = _resolveDigestOrNull(algorithm);

      final initResult = bindings.EVP_DigestSignInit(
        ctx,
        nullptr,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(bindings, initResult,
          msg: 'EVP_DigestSignInit failed');

      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);

      final updateResult = bindings.EVP_DigestSignUpdate(
        ctx,
        dataPtr.cast(),
        data.length,
      );
      calloc.free(dataPtr);
      SslObject.checkCode(bindings, updateResult,
          msg: 'EVP_DigestSignUpdate failed');

      final lenPtr = calloc<Size>();
      final finalLenResult = bindings.EVP_DigestSignFinal(ctx, nullptr, lenPtr);
      SslObject.checkCode(bindings, finalLenResult,
          msg: 'EVP_DigestSignFinal (length) failed');

      final sigLen = lenPtr.value;
      final sigPtr = calloc<Uint8>(sigLen);

      final finalResult =
          bindings.EVP_DigestSignFinal(ctx, sigPtr.cast(), lenPtr);
      if (finalResult <= 0) {
        calloc.free(lenPtr);
        calloc.free(sigPtr);
        throw OpenSslException('EVP_DigestSignFinal failed');
      }

      final signature = Uint8List.fromList(sigPtr.asTypedList(lenPtr.value));

      calloc.free(lenPtr);
      calloc.free(sigPtr);

      return signature;
    } finally {
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// Signs [data] in one-shot mode (no Update calls).
  ///
  /// Use [algorithm] = `null` for ML-DSA/EdDSA style signing where OpenSSL
  /// requires a NULL digest.
  Uint8List signOneShot(
    EvpPkey key,
    Uint8List data, {
    String? algorithm,
    MlDsaSignatureOptions? mlDsaOptions,
  }) {
    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    final pctx = calloc<Pointer<EVP_PKEY_CTX>>();
    try {
      final md = _resolveDigestOrNull(algorithm);
      final initResult = bindings.EVP_DigestSignInit(
        ctx,
        pctx,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(bindings, initResult,
          msg: 'EVP_DigestSignInit failed');

      if (mlDsaOptions != null) {
        _applyMlDsaSignatureParams(
          pkeyCtx: pctx.value,
          options: mlDsaOptions,
          forSign: true,
        );
      }

      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      try {
        final lenPtr = calloc<Size>();
        try {
          final lenResult = bindings.EVP_DigestSign(
            ctx,
            nullptr,
            lenPtr,
            dataPtr.cast(),
            data.length,
          );
          SslObject.checkCode(bindings, lenResult,
              msg: 'EVP_DigestSign (length) failed');

          final sigPtr = calloc<Uint8>(lenPtr.value);
          try {
            final signResult = bindings.EVP_DigestSign(
              ctx,
              sigPtr.cast(),
              lenPtr,
              dataPtr.cast(),
              data.length,
            );
            SslObject.checkCode(bindings, signResult,
                msg: 'EVP_DigestSign failed');
            return Uint8List.fromList(sigPtr.asTypedList(lenPtr.value));
          } finally {
            calloc.free(sigPtr);
          }
        } finally {
          calloc.free(lenPtr);
        }
      } finally {
        calloc.free(dataPtr);
      }
    } finally {
      calloc.free(pctx);
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// Verifies [signature] for [data] using [key].
  ///
  /// Returns true if valid, false otherwise.
  ///
  /// As in [sign], keys that sign the message directly (Ed25519, Ed448,
  /// ML-DSA) are routed to [verifyOneShot], which is what OpenSSL requires for
  /// them.
  bool verify(
    EvpPkey key,
    Uint8List data,
    Uint8List signature, {
    String algorithm = 'SHA256',
    bool allowOneShotFallback = true,
  }) {
    if (allowOneShotFallback && keyRequiresOneShotSignature(key)) {
      return verifyOneShot(key, data, signature);
    }

    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    try {
      final md = _resolveDigestOrNull(algorithm);

      final initResult = bindings.EVP_DigestVerifyInit(
        ctx,
        nullptr,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(bindings, initResult,
          msg: 'EVP_DigestVerifyInit failed');

      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);

      final updateResult = bindings.EVP_DigestVerifyUpdate(
        ctx,
        dataPtr.cast(),
        data.length,
      );
      calloc.free(dataPtr);
      SslObject.checkCode(bindings, updateResult,
          msg: 'EVP_DigestVerifyUpdate failed');

      final sigPtr = calloc<Uint8>(signature.length);
      sigPtr.asTypedList(signature.length).setAll(0, signature);

      final verifyResult = bindings.EVP_DigestVerifyFinal(
        ctx,
        sigPtr.cast(),
        signature.length,
      );

      calloc.free(sigPtr);

      if (verifyResult == 1) return true;
      if (verifyResult == 0) return false;

      SslObject.checkCode(bindings, verifyResult,
          msg: 'EVP_DigestVerifyFinal error');
      return false;
    } finally {
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// Verifies [signature] for [data] in one-shot mode (no Update calls).
  ///
  /// Use [algorithm] = `null` for ML-DSA/EdDSA style verification where
  /// OpenSSL requires a NULL digest.
  bool verifyOneShot(
    EvpPkey key,
    Uint8List data,
    Uint8List signature, {
    String? algorithm,
    MlDsaSignatureOptions? mlDsaOptions,
  }) {
    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    final pctx = calloc<Pointer<EVP_PKEY_CTX>>();
    try {
      final md = _resolveDigestOrNull(algorithm);
      final initResult = bindings.EVP_DigestVerifyInit(
        ctx,
        pctx,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(bindings, initResult,
          msg: 'EVP_DigestVerifyInit failed');

      if (mlDsaOptions != null) {
        _applyMlDsaSignatureParams(
          pkeyCtx: pctx.value,
          options: mlDsaOptions,
          forSign: false,
        );
      }

      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      final sigPtr = calloc<Uint8>(signature.length);
      sigPtr.asTypedList(signature.length).setAll(0, signature);
      try {
        final verifyResult = bindings.EVP_DigestVerify(
          ctx,
          sigPtr.cast(),
          signature.length,
          dataPtr.cast(),
          data.length,
        );
        if (verifyResult == 1) return true;
        if (verifyResult == 0) return false;
        SslObject.checkCode(bindings, verifyResult,
            msg: 'EVP_DigestVerify error');
        return false;
      } finally {
        calloc.free(sigPtr);
        calloc.free(dataPtr);
      }
    } finally {
      calloc.free(pctx);
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// High-level ML-DSA one-shot sign helper.
  ///
  /// Uses `algorithm: null` as required by OpenSSL for ML-DSA digest APIs.
  Uint8List signMlDsa(
    EvpPkey key,
    Uint8List data, {
    MlDsaSignatureOptions? options,
  }) {
    return signOneShot(
      key,
      data,
      algorithm: null,
      mlDsaOptions: options,
    );
  }

  /// High-level ML-DSA one-shot verify helper.
  ///
  /// Uses `algorithm: null` as required by OpenSSL for ML-DSA digest APIs.
  bool verifyMlDsa(
    EvpPkey key,
    Uint8List data,
    Uint8List signature, {
    MlDsaSignatureOptions? options,
  }) {
    return verifyOneShot(
      key,
      data,
      signature,
      algorithm: null,
      mlDsaOptions: options,
    );
  }
}
