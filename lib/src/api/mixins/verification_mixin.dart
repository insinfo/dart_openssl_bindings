import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../openssl.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../x509/x509_certificate.dart';
import '../../x509/x509_crl.dart';

/// Outcome of [VerificationMixin.verifyChain].
class VerificationResult {
  /// `true` when OpenSSL accepted the chain (`X509_V_OK`).
  final bool valid;

  /// OpenSSL error code (`X509_V_ERR_*`), or `X509_V_OK` (0).
  final int errorCode;

  /// OpenSSL message for [errorCode] (`X509_verify_cert_error_string`).
  final String message;

  /// Depth at which the error happened: 0 is the certificate itself, 1 its
  /// issuer, and so on. `-1` when there was no error.
  final int depth;

  /// Subject of the certificate where the error happened, when OpenSSL
  /// reports one.
  final String? failingCertificate;

  /// Chain built by the verification, from the certificate up to the anchor.
  /// Empty when verification failed before a chain could be built.
  final List<X509Certificate> chain;

  const VerificationResult({
    required this.valid,
    required this.errorCode,
    required this.message,
    required this.depth,
    required this.chain,
    this.failingCertificate,
  });

  /// The certificate (or one in its chain) is revoked.
  bool get revoked => errorCode == X509_V_ERR_CERT_REVOKED;

  /// The certificate is outside its validity window.
  bool get expired =>
      errorCode == X509_V_ERR_CERT_HAS_EXPIRED ||
      errorCode == X509_V_ERR_CERT_NOT_YET_VALID;

  /// No trust anchor could be reached.
  bool get untrusted =>
      errorCode == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
      errorCode == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
      errorCode == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
      errorCode == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
      errorCode == X509_V_ERR_CERT_UNTRUSTED;

  /// Releases the certificates of the returned chain.
  void dispose() {
    for (final cert in chain) {
      cert.dispose();
    }
  }

  @override
  String toString() => valid
      ? 'VerificationResult(valid, chain: ${chain.length})'
      : 'VerificationResult($message, code: $errorCode, depth: $depth)';
}

/// X.509 signature and chain verification (`X509_verify_cert`).
///
/// ```dart
/// final result = openssl.verifyChain(
///   certificate: receivedCertificate,
///   anchors: [rootCa],
///   intermediates: [intermediateCa],
///   crls: [caCrl],
///   checkRevocation: true,
/// );
/// if (!result.valid) {
///   print('rejected: ${result.message} (depth ${result.depth})');
/// }
/// ```
mixin VerificationMixin on OpenSslContext {
  /// Verifies the signature of [certificate] against the public key of
  /// [issuer].
  ///
  /// Checks the signature **only**: no validity window, no revocation, no
  /// chain building. For full validation use [verifyChain].
  bool verifyCertificateSignature(
    X509Certificate certificate,
    X509Certificate issuer,
  ) {
    final pubkey = bindings.X509_get_pubkey(issuer.handle);
    if (pubkey == nullptr) {
      throw OpenSslException('X509_get_pubkey failed');
    }
    try {
      OpenSslException.clearError(bindings);
      return bindings.X509_verify(certificate.handle, pubkey) == 1;
    } finally {
      bindings.EVP_PKEY_free(pubkey);
    }
  }

  /// Verifies [certificate] against the trusted [anchors], optionally using
  /// [intermediates] to build the chain.
  ///
  /// - [crls]: revocation lists to consult. Passing CRLs without
  ///   [checkRevocation] has no effect.
  /// - [checkRevocation]: turns on `X509_V_FLAG_CRL_CHECK` (leaf certificate
  ///   only). Together with [checkRevocationChain] it also turns on
  ///   `X509_V_FLAG_CRL_CHECK_ALL`, which demands a CRL for every level — with
  ///   no CRL for one of them the result is `UNABLE_TO_GET_CRL`.
  /// - [verificationTime]: validates as if it were that instant instead of
  ///   now. Essential to check old signatures, whose certificate has expired
  ///   since but was valid at signing time.
  /// - [ignoreValidity]: disables the time check (`NO_CHECK_TIME`).
  /// - [partialChain]: accepts any certificate in [anchors] as an anchor, even
  ///   when it is not a self-signed root (`PARTIAL_CHAIN`).
  /// - [maxDepth]: limit on the number of chain levels.
  ///
  /// The certificates in [VerificationResult.chain] belong to the caller: call
  /// [VerificationResult.dispose] when done.
  VerificationResult verifyChain({
    required X509Certificate certificate,
    required List<X509Certificate> anchors,
    List<X509Certificate> intermediates = const [],
    List<X509Crl> crls = const [],
    bool checkRevocation = false,
    bool checkRevocationChain = false,
    DateTime? verificationTime,
    bool ignoreValidity = false,
    bool partialChain = false,
    int? maxDepth,
  }) {
    if (anchors.isEmpty) {
      throw ArgumentError.value(anchors, 'anchors', 'provide at least one');
    }

    final store = bindings.X509_STORE_new();
    if (store == nullptr) {
      throw OpenSslException('X509_STORE_new failed');
    }

    Pointer<X509_STORE_CTX> ctx = nullptr;
    Pointer<OPENSSL_STACK> intermediateStack = nullptr;

    try {
      for (final anchor in anchors) {
        if (bindings.X509_STORE_add_cert(store, anchor.handle) != 1) {
          throw OpenSslException('X509_STORE_add_cert failed');
        }
      }
      for (final crl in crls) {
        if (bindings.X509_STORE_add_crl(store, crl.handle) != 1) {
          throw OpenSslException('X509_STORE_add_crl failed');
        }
      }

      var flags = 0;
      if (checkRevocation || checkRevocationChain) {
        flags |= X509_V_FLAG_CRL_CHECK;
      }
      if (checkRevocationChain) {
        flags |= X509_V_FLAG_CRL_CHECK_ALL;
      }
      if (partialChain) {
        flags |= X509_V_FLAG_PARTIAL_CHAIN;
      }
      if (ignoreValidity) {
        flags |= X509_V_FLAG_NO_CHECK_TIME;
      } else if (verificationTime != null) {
        flags |= X509_V_FLAG_USE_CHECK_TIME;
      }
      if (flags != 0) {
        bindings.X509_STORE_set_flags(store, flags);
      }

      ctx = bindings.X509_STORE_CTX_new();
      if (ctx == nullptr) {
        throw OpenSslException('X509_STORE_CTX_new failed');
      }

      if (intermediates.isNotEmpty) {
        intermediateStack = _newCertStack(intermediates);
      }

      if (bindings.X509_STORE_CTX_init(
            ctx,
            store,
            certificate.handle,
            intermediateStack.cast<stack_st_X509>(),
          ) !=
          1) {
        throw OpenSslException('X509_STORE_CTX_init failed');
      }

      if (verificationTime != null && !ignoreValidity) {
        final param = bindings.X509_STORE_CTX_get0_param(ctx);
        if (param == nullptr) {
          throw OpenSslException('X509_STORE_CTX_get0_param failed');
        }
        bindings.X509_VERIFY_PARAM_set_time(
          param,
          verificationTime.toUtc().millisecondsSinceEpoch ~/ 1000,
        );
      }

      if (maxDepth != null) {
        final param = bindings.X509_STORE_CTX_get0_param(ctx);
        if (param != nullptr) {
          bindings.X509_VERIFY_PARAM_set_depth(param, maxDepth);
        }
      }

      OpenSslException.clearError(bindings);
      final result = bindings.X509_verify_cert(ctx);
      final code = bindings.X509_STORE_CTX_get_error(ctx);

      return VerificationResult(
        valid: result == 1 && code == X509_V_OK,
        errorCode: code,
        message: _errorMessage(code),
        depth: code == X509_V_OK
            ? -1
            : bindings.X509_STORE_CTX_get_error_depth(ctx),
        failingCertificate: code == X509_V_OK ? null : _currentSubject(ctx),
        chain: result == 1 ? _chainFromContext(ctx) : const [],
      );
    } finally {
      if (ctx != nullptr) {
        bindings.X509_STORE_CTX_free(ctx);
      }
      if (intermediateStack != nullptr) {
        bindings.OPENSSL_sk_free(intermediateStack.cast());
      }
      bindings.X509_STORE_free(store);
      OpenSslException.clearError(bindings);
    }
  }

  String _errorMessage(int code) {
    final ptr = bindings.X509_verify_cert_error_string(code);
    if (ptr == nullptr) return 'error $code';
    return ptr.cast<Utf8>().toDartString();
  }

  String? _currentSubject(Pointer<X509_STORE_CTX> ctx) {
    final cert = bindings.X509_STORE_CTX_get_current_cert(ctx);
    if (cert == nullptr) return null;

    final buffer = calloc<Char>(512);
    try {
      final ptr = bindings.X509_NAME_oneline(
        bindings.X509_get_subject_name(cert),
        buffer,
        512,
      );
      if (ptr == nullptr) return null;
      return ptr.cast<Utf8>().toDartString();
    } finally {
      calloc.free(buffer);
    }
  }

  List<X509Certificate> _chainFromContext(Pointer<X509_STORE_CTX> ctx) {
    final stack = bindings.X509_STORE_CTX_get0_chain(ctx);
    if (stack == nullptr) return const [];

    final total = bindings.OPENSSL_sk_num(stack.cast());
    final chain = <X509Certificate>[];
    for (var i = 0; i < total; i++) {
      final item = bindings.OPENSSL_sk_value(stack.cast(), i);
      if (item == nullptr) continue;
      // get0 returns references owned by the context, which dies in the
      // finally block below: duplicate them.
      final copy = bindings.X509_dup(item.cast<X509>());
      if (copy == nullptr) continue;
      chain.add(X509Certificate(copy, this as OpenSSL));
    }
    return chain;
  }

  Pointer<OPENSSL_STACK> _newCertStack(List<X509Certificate> certificates) {
    final stack = bindings.OPENSSL_sk_new_null();
    if (stack == nullptr) {
      throw OpenSslException('OPENSSL_sk_new_null failed');
    }
    for (final cert in certificates) {
      if (bindings.OPENSSL_sk_push(stack.cast(), cert.handle.cast()) == 0) {
        bindings.OPENSSL_sk_free(stack.cast());
        throw OpenSslException('OPENSSL_sk_push failed');
      }
    }
    return stack.cast();
  }
}
