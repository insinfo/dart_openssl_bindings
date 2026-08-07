import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl_context.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../crypto/evp_pkey.dart';
import '../x509/x509_certificate.dart';

/// Status of a time-stamp response (RFC 3161, `PKIStatus`).
enum TimestampStatus {
  /// The token was issued as requested.
  granted(TS_STATUS_GRANTED),

  /// The token was issued, but with modifications to the request.
  grantedWithMods(TS_STATUS_GRANTED_WITH_MODS),

  /// The request was rejected; see [TimestampResponse.failureInfo].
  rejection(TS_STATUS_REJECTION),

  /// The request was accepted and the token will come later.
  waiting(TS_STATUS_WAITING),

  /// The TSA warns that revocation is imminent.
  revocationWarning(TS_STATUS_REVOCATION_WARNING),

  /// The TSA reports that a certificate has been revoked.
  revocationNotification(TS_STATUS_REVOCATION_NOTIFICATION);

  const TimestampStatus(this.code);

  /// Numeric `PKIStatus` value.
  final int code;

  /// Whether a token was actually issued.
  bool get isGranted =>
      this == TimestampStatus.granted || this == TimestampStatus.grantedWithMods;

  /// Maps a numeric `PKIStatus`, defaulting to [rejection] for unknown values.
  static TimestampStatus fromCode(int code) => TimestampStatus.values.firstWhere(
        (status) => status.code == code,
        orElse: () => TimestampStatus.rejection,
      );
}

/// A time-stamp request (RFC 3161 `TimeStampReq`).
class TimestampRequest {
  /// DER encoding, ready to be posted to the TSA
  /// (`Content-Type: application/timestamp-query`).
  final Uint8List der;

  /// Hash that was time-stamped (the message imprint).
  final Uint8List hash;

  /// Digest algorithm of [hash], as OpenSSL names it (`SHA256`, ...).
  final String hashAlgorithm;

  /// Nonce sent to the TSA, or `null` when none was requested.
  ///
  /// Keep it: matching the nonce in the answer is what proves the token was
  /// minted for this request and is not a replay.
  final BigInt? nonce;

  /// Requested policy OID, or `null` for the TSA default.
  final String? policyOid;

  /// Whether the TSA was asked to include its certificate in the token.
  final bool requestCertificate;

  const TimestampRequest({
    required this.der,
    required this.hash,
    required this.hashAlgorithm,
    required this.nonce,
    required this.policyOid,
    required this.requestCertificate,
  });

  @override
  String toString() => 'TimestampRequest($hashAlgorithm, '
      '${der.length} bytes${nonce == null ? '' : ', with nonce'})';
}

/// Accuracy declared by the TSA for the time in a token.
class TimestampAccuracy {
  /// Seconds component.
  final int seconds;

  /// Milliseconds component.
  final int millis;

  /// Microseconds component.
  final int micros;

  const TimestampAccuracy({
    this.seconds = 0,
    this.millis = 0,
    this.micros = 0,
  });

  /// The accuracy as a [Duration].
  Duration get asDuration => Duration(
        seconds: seconds,
        milliseconds: millis,
        microseconds: micros,
      );

  @override
  String toString() => 'TimestampAccuracy(${asDuration.inMicroseconds}us)';
}

/// The `TSTInfo` carried by a time-stamp token.
class TimestampToken {
  /// DER of the token itself (a CMS/PKCS#7 SignedData), which is what gets
  /// archived alongside the signature.
  final Uint8List der;

  /// Time asserted by the TSA, in UTC.
  final DateTime genTime;

  /// Serial number assigned by the TSA.
  final BigInt serialNumber;

  /// Policy under which the token was issued.
  final String policyOid;

  /// Digest algorithm of [messageImprint].
  final String hashAlgorithm;

  /// The hash that was time-stamped.
  final Uint8List messageImprint;

  /// Nonce echoed back from the request, or `null` when there was none.
  final BigInt? nonce;

  /// Declared accuracy of [genTime], or `null` when the TSA omitted it.
  final TimestampAccuracy? accuracy;

  /// `ordering` flag: whether tokens from this TSA can be ordered by time
  /// alone, without comparing accuracies.
  final bool ordering;

  /// `TSTInfo` version, normally 1.
  final int version;

  const TimestampToken({
    required this.der,
    required this.genTime,
    required this.serialNumber,
    required this.policyOid,
    required this.hashAlgorithm,
    required this.messageImprint,
    required this.nonce,
    required this.accuracy,
    required this.ordering,
    required this.version,
  });

  @override
  String toString() => 'TimestampToken($hashAlgorithm, '
      'genTime: ${genTime.toIso8601String()}, serial: $serialNumber)';
}

/// A parsed time-stamp response (RFC 3161 `TimeStampResp`).
class TimestampResponse {
  /// DER of the whole response, as returned by the TSA.
  final Uint8List der;

  /// Status reported by the TSA.
  final TimestampStatus status;

  /// Free-form text explaining the status, when the TSA sent one.
  final String? statusText;

  /// `PKIFailureInfo` bits, when the request was rejected.
  final int? failureInfo;

  /// The issued token, or `null` when the request was not granted.
  final TimestampToken? token;

  const TimestampResponse({
    required this.der,
    required this.status,
    required this.statusText,
    required this.failureInfo,
    required this.token,
  });

  /// Whether a token was issued.
  bool get isGranted => status.isGranted && token != null;

  @override
  String toString() => 'TimestampResponse(${status.name}'
      '${statusText == null ? '' : ': $statusText'})';
}

/// Outcome of [TimestampMixin.verifyTimestamp].
class TimestampVerification {
  /// Whether OpenSSL accepted the token.
  final bool valid;

  /// Reason for the rejection, straight from OpenSSL's error queue.
  final String? error;

  /// The token that was checked, when it could be parsed at all.
  final TimestampToken? token;

  const TimestampVerification({
    required this.valid,
    required this.error,
    required this.token,
  });

  @override
  String toString() =>
      valid ? 'TimestampVerification(valid, $token)' : 'TimestampVerification($error)';
}

/// RFC 3161 time-stamping: requesting, issuing and verifying tokens.
///
/// Client side:
///
/// ```dart
/// final request = openssl.buildTimestampRequest(hash: sha256OfTheSignature);
/// final answer = await postToTsa(request.der);          // your HTTP call
/// final response = openssl.parseTimestampResponse(answer);
///
/// final check = openssl.verifyTimestamp(
///   responseDer: answer,
///   hash: sha256OfTheSignature,
///   nonce: request.nonce,
///   anchors: [tsaRootCa],
/// );
/// ```
///
/// Server side (an internal TSA, signing with a certificate that carries
/// `extendedKeyUsage = critical, timeStamping`):
///
/// ```dart
/// final response = openssl.createTimestampResponse(
///   requestDer: incomingRequest,
///   signerCertificate: tsaCertificate,
///   signerKey: tsaKey,
///   defaultPolicyOid: '1.3.6.1.4.1.99999.1.1',
///   serialNumber: nextSerialFromTheDatabase,
/// );
/// ```
mixin TimestampMixin on OpenSslContext {
  /// Builds a `TimeStampReq` for [hash].
  ///
  /// [hash] must be the digest of the data being time-stamped, computed with
  /// [hashAlgorithm] — its length is checked against the algorithm.
  ///
  /// [nonce] defaults to 64 fresh random bits. Sending one and checking it in
  /// the answer is the defence against a replayed token; pass `false` to
  /// [useNonce] only when talking to a TSA that rejects nonces.
  ///
  /// [requestCertificate] asks the TSA to embed its certificate in the token,
  /// which is what makes the token verifiable on its own later.
  TimestampRequest buildTimestampRequest({
    required Uint8List hash,
    String hashAlgorithm = 'SHA256',
    String? policyOid,
    bool requestCertificate = true,
    bool useNonce = true,
    BigInt? nonce,
  }) {
    final md = _digestByName(hashAlgorithm);
    final expected = bindings.EVP_MD_get_size(md);
    if (expected > 0 && hash.length != expected) {
      throw ArgumentError.value(
        hash.length,
        'hash.length',
        'a $hashAlgorithm imprint must be $expected bytes',
      );
    }

    final effectiveNonce =
        nonce ?? (useNonce ? _randomNonce() : null);

    final req = bindings.TS_REQ_new();
    if (req == nullptr) {
      throw OpenSslException('TS_REQ_new failed');
    }

    Pointer<TS_MSG_IMPRINT> imprint = nullptr;
    Pointer<X509_ALGOR> algor = nullptr;
    Pointer<ASN1_INTEGER> nonceInt = nullptr;
    Pointer<ASN1_OBJECT> policy = nullptr;

    try {
      if (bindings.TS_REQ_set_version(req, 1) != 1) {
        throw OpenSslException('TS_REQ_set_version failed');
      }

      imprint = bindings.TS_MSG_IMPRINT_new();
      if (imprint == nullptr) {
        throw OpenSslException('TS_MSG_IMPRINT_new failed');
      }

      algor = bindings.X509_ALGOR_new();
      if (algor == nullptr) {
        throw OpenSslException('X509_ALGOR_new failed');
      }
      // X509_ALGOR_set_md returns void: it cannot fail for a fetched digest.
      bindings.X509_ALGOR_set_md(algor, md);
      if (bindings.TS_MSG_IMPRINT_set_algo(imprint, algor) != 1) {
        throw OpenSslException('TS_MSG_IMPRINT_set_algo failed');
      }

      final hashPtr = calloc<UnsignedChar>(hash.length);
      try {
        hashPtr.cast<Uint8>().asTypedList(hash.length).setAll(0, hash);
        if (bindings.TS_MSG_IMPRINT_set_msg(imprint, hashPtr, hash.length) !=
            1) {
          throw OpenSslException('TS_MSG_IMPRINT_set_msg failed');
        }
      } finally {
        calloc.free(hashPtr);
      }

      if (bindings.TS_REQ_set_msg_imprint(req, imprint) != 1) {
        throw OpenSslException('TS_REQ_set_msg_imprint failed');
      }

      if (effectiveNonce != null) {
        nonceInt = _asn1IntegerFromBigInt(effectiveNonce);
        if (bindings.TS_REQ_set_nonce(req, nonceInt) != 1) {
          throw OpenSslException('TS_REQ_set_nonce failed');
        }
      }

      if (policyOid != null) {
        policy = _objFromOid(policyOid);
        if (bindings.TS_REQ_set_policy_id(req, policy) != 1) {
          throw OpenSslException('TS_REQ_set_policy_id failed');
        }
      }

      if (bindings.TS_REQ_set_cert_req(req, requestCertificate ? 1 : 0) != 1) {
        throw OpenSslException('TS_REQ_set_cert_req failed');
      }

      return TimestampRequest(
        der: _encode(
          (out) => bindings.i2d_TS_REQ(req, out),
          'i2d_TS_REQ',
        ),
        hash: Uint8List.fromList(hash),
        hashAlgorithm: hashAlgorithm,
        nonce: effectiveNonce,
        policyOid: policyOid,
        requestCertificate: requestCertificate,
      );
    } finally {
      if (nonceInt != nullptr) bindings.ASN1_INTEGER_free(nonceInt);
      if (policy != nullptr) bindings.ASN1_OBJECT_free(policy);
      // The imprint (and with it the algorithm) belongs to the request once
      // set; when set failed, free it here.
      if (imprint != nullptr &&
          bindings.TS_REQ_get_msg_imprint(req) != imprint) {
        bindings.TS_MSG_IMPRINT_free(imprint);
      } else if (algor != nullptr && imprint == nullptr) {
        bindings.X509_ALGOR_free(algor);
      }
      bindings.TS_REQ_free(req);
    }
  }

  /// Parses a `TimeStampResp` returned by a TSA.
  TimestampResponse parseTimestampResponse(Uint8List der) {
    final arena = Arena();
    Pointer<TS_RESP> resp = nullptr;

    try {
      resp = _d2i(
        der,
        arena,
        (inOut, len) => bindings.d2i_TS_RESP(nullptr, inOut, len),
        'd2i_TS_RESP',
      );

      final statusInfo = bindings.TS_RESP_get_status_info(resp);
      if (statusInfo == nullptr) {
        throw OpenSslException('TS_RESP_get_status_info failed');
      }

      final statusValue =
          _bigIntFromAsn1(bindings.TS_STATUS_INFO_get0_status(statusInfo));
      final status = TimestampStatus.fromCode(statusValue?.toInt() ?? -1);

      TimestampToken? token;
      if (status.isGranted) {
        final tstInfo = bindings.TS_RESP_get_tst_info(resp);
        final pkcs7 = bindings.TS_RESP_get_token(resp);
        if (tstInfo != nullptr && pkcs7 != nullptr) {
          token = _readTstInfo(
            tstInfo,
            _encode((out) => bindings.i2d_PKCS7(pkcs7, out), 'i2d_PKCS7'),
          );
        }
      }

      return TimestampResponse(
        der: Uint8List.fromList(der),
        status: status,
        statusText: _statusText(statusInfo),
        failureInfo: _failureInfo(statusInfo),
        token: token,
      );
    } finally {
      if (resp != nullptr) bindings.TS_RESP_free(resp);
      arena.releaseAll();
    }
  }

  /// Parses a bare token (the CMS/PKCS#7 `TimeStampToken`), without the
  /// response envelope — the shape usually archived next to a signature.
  TimestampToken parseTimestampToken(Uint8List tokenDer) {
    final arena = Arena();
    Pointer<PKCS7> token = nullptr;
    Pointer<TS_TST_INFO> tstInfo = nullptr;

    try {
      token = _d2i(
        tokenDer,
        arena,
        (inOut, len) => bindings.d2i_PKCS7(nullptr, inOut, len),
        'd2i_PKCS7',
      );

      tstInfo = bindings.PKCS7_to_TS_TST_INFO(token);
      if (tstInfo == nullptr) {
        throw OpenSslException(
          'Not an RFC 3161 time-stamp token',
          bindings.ERR_get_error(),
          'PKCS7_to_TS_TST_INFO',
        );
      }

      return _readTstInfo(tstInfo, Uint8List.fromList(tokenDer));
    } finally {
      if (tstInfo != nullptr) bindings.TS_TST_INFO_free(tstInfo);
      if (token != nullptr) bindings.PKCS7_free(token);
      arena.releaseAll();
    }
  }

  /// Verifies a time-stamp token against [hash] and a set of trust [anchors].
  ///
  /// Pass either [responseDer] (the whole `TimeStampResp`) or [tokenDer] (the
  /// bare token). [hash], [hashAlgorithm], [nonce] and [policyOid] describe
  /// the request the token is supposed to answer: OpenSSL checks the signature,
  /// the message imprint, the nonce and the policy against them, and builds a
  /// chain from the TSA certificate up to [anchors].
  ///
  /// When verifying an archived token whose request is long gone, leave
  /// [nonce] as `null` — the nonce check is then skipped, and everything else
  /// still holds.
  TimestampVerification verifyTimestamp({
    Uint8List? responseDer,
    Uint8List? tokenDer,
    required Uint8List hash,
    required List<X509Certificate> anchors,
    String hashAlgorithm = 'SHA256',
    BigInt? nonce,
    String? policyOid,
    List<X509Certificate> intermediates = const [],
    bool checkSignerName = false,
  }) {
    if ((responseDer == null) == (tokenDer == null)) {
      throw ArgumentError('provide exactly one of responseDer or tokenDer');
    }
    if (anchors.isEmpty) {
      throw ArgumentError.value(anchors, 'anchors', 'provide at least one');
    }

    final arena = Arena();
    Pointer<TS_REQ> req = nullptr;
    Pointer<TS_VERIFY_CTX> ctx = nullptr;
    Pointer<TS_RESP> resp = nullptr;
    Pointer<PKCS7> token = nullptr;

    try {
      // TS_REQ_to_TS_VERIFY_CTX is the only way to set the expected imprint
      // together with its digest algorithm, so the request is rebuilt here
      // from what the caller knows.
      final template = buildTimestampRequest(
        hash: hash,
        hashAlgorithm: hashAlgorithm,
        policyOid: policyOid,
        useNonce: false,
        nonce: nonce,
      );
      req = _d2i(
        template.der,
        arena,
        (inOut, len) => bindings.d2i_TS_REQ(nullptr, inOut, len),
        'd2i_TS_REQ',
      );

      ctx = bindings.TS_REQ_to_TS_VERIFY_CTX(req, nullptr);
      if (ctx == nullptr) {
        throw OpenSslException('TS_REQ_to_TS_VERIFY_CTX failed');
      }

      var flags = TS_VFY_SIGNATURE | TS_VFY_VERSION | TS_VFY_IMPRINT;
      if (nonce != null) flags |= TS_VFY_NONCE;
      if (policyOid != null) flags |= TS_VFY_POLICY;
      if (checkSignerName) flags |= TS_VFY_SIGNER;
      bindings.TS_VERIFY_CTX_set_flags(ctx, flags);

      // The context takes ownership of the store and of the certificate stack,
      // so both are built fresh here.
      final store = bindings.X509_STORE_new();
      if (store == nullptr) {
        throw OpenSslException('X509_STORE_new failed');
      }
      for (final anchor in anchors) {
        if (bindings.X509_STORE_add_cert(store, anchor.handle) != 1) {
          bindings.X509_STORE_free(store);
          throw OpenSslException('X509_STORE_add_cert failed');
        }
      }
      if (!_setVerifyStore(ctx, store)) {
        bindings.X509_STORE_free(store);
        throw OpenSslException('TS_VERIFY_CTX_set0_store failed');
      }

      if (intermediates.isNotEmpty) {
        final stack = bindings.OPENSSL_sk_new_null();
        if (stack == nullptr) {
          throw OpenSslException('OPENSSL_sk_new_null failed');
        }
        for (final cert in intermediates) {
          final copy = bindings.X509_dup(cert.handle);
          if (copy == nullptr ||
              bindings.OPENSSL_sk_push(stack.cast(), copy.cast()) == 0) {
            throw OpenSslException('failed to stack an intermediate');
          }
        }
        if (!_setVerifyCerts(ctx, stack.cast<stack_st_X509>())) {
          throw OpenSslException('TS_VERIFY_CTX_set0_certs failed');
        }
      }

      OpenSslException.clearError(bindings);

      final int result;
      if (responseDer != null) {
        resp = _d2i(
          responseDer,
          arena,
          (inOut, len) => bindings.d2i_TS_RESP(nullptr, inOut, len),
          'd2i_TS_RESP',
        );
        result = bindings.TS_RESP_verify_response(ctx, resp);
      } else {
        token = _d2i(
          tokenDer!,
          arena,
          (inOut, len) => bindings.d2i_PKCS7(nullptr, inOut, len),
          'd2i_PKCS7',
        );
        result = bindings.TS_RESP_verify_token(ctx, token);
      }

      final parsed = responseDer != null
          ? parseTimestampResponse(responseDer).token
          : parseTimestampToken(tokenDer!);

      return TimestampVerification(
        valid: result == 1,
        error: result == 1 ? null : _drainErrors(),
        token: parsed,
      );
    } finally {
      if (resp != nullptr) bindings.TS_RESP_free(resp);
      if (token != nullptr) bindings.PKCS7_free(token);
      if (ctx != nullptr) bindings.TS_VERIFY_CTX_free(ctx);
      if (req != nullptr) bindings.TS_REQ_free(req);
      arena.releaseAll();
      OpenSslException.clearError(bindings);
    }
  }

  /// Issues a `TimeStampResp` for [requestDer] — the TSA side of RFC 3161.
  ///
  /// [signerCertificate] must carry `extendedKeyUsage = critical, timeStamping`
  /// (OID 1.3.6.1.5.5.7.3.8); OpenSSL refuses to sign with anything else.
  ///
  /// [serialNumber] is the serial the token will carry. **It must be unique per
  /// TSA**: repeating one makes two different tokens indistinguishable in an
  /// audit. Leaving it `null` falls back to OpenSSL's default callback, which
  /// always answers 1 — acceptable for a test, not for a real TSA.
  ///
  /// [acceptedDigests] limits the digests the TSA will time-stamp; the default
  /// covers the SHA-2 family. [accuracy] and [clockPrecisionDigits] describe
  /// how good the clock is, and are copied into the token.
  Uint8List createTimestampResponse({
    required Uint8List requestDer,
    required X509Certificate signerCertificate,
    required EvpPkey signerKey,
    required String defaultPolicyOid,
    BigInt? serialNumber,
    List<String> acceptedDigests = const ['SHA256', 'SHA384', 'SHA512'],
    List<String> acceptedPolicyOids = const [],
    List<X509Certificate> chain = const [],
    TimestampAccuracy? accuracy,
    int clockPrecisionDigits = 0,
    bool ordering = false,
    String signerDigest = 'SHA256',
  }) {
    final ctx = bindings.TS_RESP_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('TS_RESP_CTX_new failed');
    }

    NativeCallable<TS_serial_cbFunction>? serialCallback;
    Pointer<BIO> requestBio = nullptr;
    Pointer<TS_RESP> response = nullptr;
    Pointer<OPENSSL_STACK> chainStack = nullptr;

    try {
      if (bindings.TS_RESP_CTX_set_signer_cert(ctx, signerCertificate.handle) !=
          1) {
        throw OpenSslException(
          'TS_RESP_CTX_set_signer_cert failed: the certificate needs '
          'extendedKeyUsage = critical, timeStamping',
          bindings.ERR_get_error(),
          'TS_RESP_CTX_set_signer_cert',
        );
      }
      if (bindings.TS_RESP_CTX_set_signer_key(ctx, signerKey.handle) != 1) {
        throw OpenSslException('TS_RESP_CTX_set_signer_key failed');
      }

      final md = _digestByName(signerDigest);
      if (bindings.TS_RESP_CTX_set_signer_digest(ctx, md) != 1) {
        throw OpenSslException('TS_RESP_CTX_set_signer_digest failed');
      }

      final policy = _objFromOid(defaultPolicyOid);
      try {
        if (bindings.TS_RESP_CTX_set_def_policy(ctx, policy) != 1) {
          throw OpenSslException('TS_RESP_CTX_set_def_policy failed');
        }
      } finally {
        bindings.ASN1_OBJECT_free(policy);
      }

      for (final oid in acceptedPolicyOids) {
        final extra = _objFromOid(oid);
        try {
          if (bindings.TS_RESP_CTX_add_policy(ctx, extra) != 1) {
            throw OpenSslException('TS_RESP_CTX_add_policy failed for $oid');
          }
        } finally {
          bindings.ASN1_OBJECT_free(extra);
        }
      }

      for (final name in acceptedDigests) {
        if (bindings.TS_RESP_CTX_add_md(ctx, _digestByName(name)) != 1) {
          throw OpenSslException('TS_RESP_CTX_add_md failed for $name');
        }
      }

      if (chain.isNotEmpty) {
        chainStack = bindings.OPENSSL_sk_new_null().cast();
        if (chainStack == nullptr) {
          throw OpenSslException('OPENSSL_sk_new_null failed');
        }
        for (final cert in chain) {
          if (bindings.X509_up_ref(cert.handle) != 1 ||
              bindings.OPENSSL_sk_push(chainStack.cast(), cert.handle.cast()) ==
                  0) {
            throw OpenSslException('failed to stack a chain certificate');
          }
        }
        if (bindings.TS_RESP_CTX_set_certs(
              ctx,
              chainStack.cast<stack_st_X509>(),
            ) !=
            1) {
          throw OpenSslException('TS_RESP_CTX_set_certs failed');
        }
      }

      if (accuracy != null) {
        if (bindings.TS_RESP_CTX_set_accuracy(
              ctx,
              accuracy.seconds,
              accuracy.millis,
              accuracy.micros,
            ) !=
            1) {
          throw OpenSslException('TS_RESP_CTX_set_accuracy failed');
        }
      }

      if (clockPrecisionDigits != 0) {
        if (bindings.TS_RESP_CTX_set_clock_precision_digits(
              ctx,
              clockPrecisionDigits,
            ) !=
            1) {
          throw OpenSslException(
            'TS_RESP_CTX_set_clock_precision_digits failed',
          );
        }
      }

      if (ordering) {
        bindings.TS_RESP_CTX_add_flags(ctx, TS_ORDERING);
      }

      if (serialNumber != null) {
        // OpenSSL asks for the serial through a callback; hand it one that
        // answers with the number the caller reserved.
        final ffi = bindings;
        serialCallback = NativeCallable<TS_serial_cbFunction>.isolateLocal(
          (Pointer<TS_resp_ctx> _, Pointer<Void> __) =>
              _asn1IntegerFromBigIntWith(ffi, serialNumber),
        );
        bindings.TS_RESP_CTX_set_serial_cb(
          ctx,
          serialCallback.nativeFunction,
          nullptr,
        );
      }

      requestBio = _bioFromBytes(requestDer);
      response = bindings.TS_RESP_create_response(ctx, requestBio);
      if (response == nullptr) {
        throw OpenSslException(
          'TS_RESP_create_response failed',
          bindings.ERR_get_error(),
          'TS_RESP_create_response',
        );
      }

      return _encode(
        (out) => bindings.i2d_TS_RESP(response, out),
        'i2d_TS_RESP',
      );
    } finally {
      if (response != nullptr) bindings.TS_RESP_free(response);
      if (requestBio != nullptr) bindings.BIO_free(requestBio);
      serialCallback?.close();
      bindings.TS_RESP_CTX_free(ctx);
      // The stack itself is owned by the context after set_certs; when the
      // call never happened, drop it here (the certificates keep their
      // reference counts balanced by X509_up_ref above).
      if (chainStack != nullptr && chain.isEmpty) {
        bindings.OPENSSL_sk_free(chainStack.cast());
      }
    }
  }

  /// Convenience for the common case: hash [data], ask the TSA and return the
  /// request to post.
  TimestampRequest buildTimestampRequestForData(
    Uint8List data, {
    String hashAlgorithm = 'SHA256',
    String? policyOid,
    bool requestCertificate = true,
  }) =>
      buildTimestampRequest(
        hash: _digest(data, hashAlgorithm),
        hashAlgorithm: hashAlgorithm,
        policyOid: policyOid,
        requestCertificate: requestCertificate,
      );

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  /// Hands the trust store to the verification context.
  ///
  /// `TS_VERIFY_CTX_set0_store` only exists from OpenSSL 3.4 on; older
  /// libraries (the Ubuntu LTS ships 3.0) expose the same thing under
  /// `TS_VERIFY_CTX_set_store`, which returns the previous value instead of a
  /// status. Either way the context takes ownership of the store.
  bool _setVerifyStore(Pointer<TS_VERIFY_CTX> ctx, Pointer<X509_STORE> store) {
    try {
      return bindings.TS_VERIFY_CTX_set0_store(ctx, store) == 1;
    } on ArgumentError {
      bindings.TS_VERIFY_CTX_set_store(ctx, store);
      return true;
    }
  }

  /// Same story as [_setVerifyStore], for the certificate stack.
  bool _setVerifyCerts(
    Pointer<TS_VERIFY_CTX> ctx,
    Pointer<stack_st_X509> certs,
  ) {
    try {
      return bindings.TS_VERIFY_CTX_set0_certs(ctx, certs) == 1;
    } on ArgumentError {
      bindings.TS_VERIFY_CTX_set_certs(ctx, certs);
      return true;
    }
  }

  TimestampToken _readTstInfo(Pointer<TS_TST_INFO> info, Uint8List der) {
    final imprint = bindings.TS_TST_INFO_get_msg_imprint(info);
    if (imprint == nullptr) {
      throw OpenSslException('TS_TST_INFO_get_msg_imprint failed');
    }

    final msg = bindings.TS_MSG_IMPRINT_get_msg(imprint);
    final msgLen = bindings.ASN1_STRING_length(msg.cast());
    final msgData = bindings.ASN1_STRING_get0_data(msg.cast());

    final accuracy = bindings.TS_TST_INFO_get_accuracy(info);

    return TimestampToken(
      der: der,
      genTime: _generalizedTimeToDateTime(bindings.TS_TST_INFO_get_time(info)),
      serialNumber:
          _bigIntFromAsn1(bindings.TS_TST_INFO_get_serial(info)) ?? BigInt.zero,
      policyOid: _oidOfObject(bindings.TS_TST_INFO_get_policy_id(info)),
      hashAlgorithm: _algorithmName(bindings.TS_MSG_IMPRINT_get_algo(imprint)),
      messageImprint: msgLen <= 0
          ? Uint8List(0)
          : Uint8List.fromList(msgData.cast<Uint8>().asTypedList(msgLen)),
      nonce: _bigIntFromAsn1(bindings.TS_TST_INFO_get_nonce(info)),
      accuracy: accuracy == nullptr
          ? null
          : TimestampAccuracy(
              seconds:
                  _bigIntFromAsn1(bindings.TS_ACCURACY_get_seconds(accuracy))
                          ?.toInt() ??
                      0,
              millis: _bigIntFromAsn1(bindings.TS_ACCURACY_get_millis(accuracy))
                      ?.toInt() ??
                  0,
              micros: _bigIntFromAsn1(bindings.TS_ACCURACY_get_micros(accuracy))
                      ?.toInt() ??
                  0,
            ),
      ordering: bindings.TS_TST_INFO_get_ordering(info) != 0,
      version: bindings.TS_TST_INFO_get_version(info),
    );
  }

  String? _statusText(Pointer<TS_STATUS_INFO> statusInfo) {
    final texts = bindings.TS_STATUS_INFO_get0_text(statusInfo);
    if (texts == nullptr) return null;

    final count = bindings.OPENSSL_sk_num(texts.cast());
    if (count <= 0) return null;

    final parts = <String>[];
    for (var i = 0; i < count; i++) {
      final item = bindings.OPENSSL_sk_value(texts.cast(), i);
      if (item == nullptr) continue;
      final len = bindings.ASN1_STRING_length(item.cast());
      final data = bindings.ASN1_STRING_get0_data(item.cast());
      if (len <= 0 || data == nullptr) continue;
      parts.add(String.fromCharCodes(data.cast<Uint8>().asTypedList(len)));
    }
    return parts.isEmpty ? null : parts.join('; ');
  }

  int? _failureInfo(Pointer<TS_STATUS_INFO> statusInfo) {
    final bits = bindings.TS_STATUS_INFO_get0_failure_info(statusInfo);
    if (bits == nullptr) return null;

    final len = bindings.ASN1_STRING_length(bits.cast());
    final data = bindings.ASN1_STRING_get0_data(bits.cast());
    if (len <= 0 || data == nullptr) return null;

    var value = 0;
    final bytes = data.cast<Uint8>().asTypedList(len);
    for (final b in bytes) {
      value = (value << 8) | b;
    }
    return value;
  }

  DateTime _generalizedTimeToDateTime(Pointer<ASN1_GENERALIZEDTIME> time) {
    if (time == nullptr) {
      throw OpenSslException('time-stamp token without genTime');
    }

    final len = bindings.ASN1_STRING_length(time.cast());
    final data = bindings.ASN1_STRING_get0_data(time.cast());
    if (len <= 0 || data == nullptr) {
      throw OpenSslException('empty genTime in the time-stamp token');
    }

    // GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
    final text = String.fromCharCodes(data.cast<Uint8>().asTypedList(len));
    final match = RegExp(
      r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z?$',
    ).firstMatch(text);
    if (match == null) {
      throw OpenSslException('unsupported genTime format: $text');
    }

    final fraction = match.group(7);
    final micros = fraction == null
        ? 0
        : int.parse(fraction.padRight(6, '0').substring(0, 6));

    return DateTime.utc(
      int.parse(match.group(1)!),
      int.parse(match.group(2)!),
      int.parse(match.group(3)!),
      int.parse(match.group(4)!),
      int.parse(match.group(5)!),
      int.parse(match.group(6)!),
      micros ~/ 1000,
      micros % 1000,
    );
  }

  String _oidOfObject(Pointer<ASN1_OBJECT> obj) {
    if (obj == nullptr) return '';
    final buffer = calloc<Char>(128);
    try {
      final len = bindings.OBJ_obj2txt(buffer, 128, obj, 1);
      if (len <= 0) return '';
      return buffer.cast<Utf8>().toDartString();
    } finally {
      calloc.free(buffer);
    }
  }

  String _algorithmName(Pointer<X509_ALGOR> algor) {
    if (algor == nullptr) return '';
    final objPtr = calloc<Pointer<ASN1_OBJECT>>();
    try {
      bindings.X509_ALGOR_get0(objPtr, nullptr, nullptr, algor);
      final obj = objPtr.value;
      if (obj == nullptr) return '';
      final nid = bindings.OBJ_obj2nid(obj);
      final shortName = bindings.OBJ_nid2sn(nid);
      if (shortName != nullptr) {
        return shortName.cast<Utf8>().toDartString().toUpperCase();
      }
      return _oidOfObject(obj);
    } finally {
      calloc.free(objPtr);
    }
  }

  Pointer<EVP_MD> _digestByName(String name) {
    final namePtr = name.toNativeUtf8(allocator: calloc);
    try {
      final md = bindings.EVP_get_digestbyname(namePtr.cast());
      if (md == nullptr) {
        throw ArgumentError.value(name, 'algorithm', 'unknown digest');
      }
      return md;
    } finally {
      calloc.free(namePtr);
    }
  }

  Uint8List _digest(Uint8List data, String algorithm) {
    final md = _digestByName(algorithm);
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('EVP_MD_CTX_new failed');
    }

    final out = calloc<UnsignedChar>(64);
    final outLen = calloc<UnsignedInt>();
    final dataPtr = calloc<Uint8>(data.length);
    try {
      dataPtr.asTypedList(data.length).setAll(0, data);
      if (bindings.EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
          bindings.EVP_DigestUpdate(ctx, dataPtr.cast(), data.length) != 1 ||
          bindings.EVP_DigestFinal_ex(ctx, out, outLen) != 1) {
        throw OpenSslException('failed to digest with $algorithm');
      }
      return Uint8List.fromList(
        out.cast<Uint8>().asTypedList(outLen.value),
      );
    } finally {
      calloc.free(dataPtr);
      calloc.free(outLen);
      calloc.free(out);
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  Pointer<ASN1_OBJECT> _objFromOid(String oid) {
    final oidPtr = oid.toNativeUtf8(allocator: calloc);
    try {
      final obj = bindings.OBJ_txt2obj(oidPtr.cast(), 1);
      if (obj == nullptr) {
        throw ArgumentError.value(oid, 'oid', 'not a valid OID');
      }
      return obj;
    } finally {
      calloc.free(oidPtr);
    }
  }

  BigInt _randomNonce() {
    final bytes = calloc<UnsignedChar>(8);
    try {
      if (bindings.RAND_bytes(bytes, 8) != 1) {
        throw OpenSslException('RAND_bytes failed');
      }
      final list = bytes.cast<Uint8>().asTypedList(8);
      var value = BigInt.zero;
      for (final b in list) {
        value = (value << 8) | BigInt.from(b);
      }
      // Keep it positive and non-zero: a zero nonce is indistinguishable from
      // "no nonce" once DER-encoded.
      return value.isEven ? value + BigInt.one : value;
    } finally {
      calloc.free(bytes);
    }
  }

  Pointer<ASN1_INTEGER> _asn1IntegerFromBigInt(BigInt value) =>
      _asn1IntegerFromBigIntWith(bindings, value);

  Pointer<BIO> _bioFromBytes(Uint8List bytes) {
    final bio = bindings.BIO_new(bindings.BIO_s_mem());
    if (bio == nullptr) {
      throw OpenSslException('BIO_new failed');
    }
    final ptr = calloc<Uint8>(bytes.length);
    try {
      ptr.asTypedList(bytes.length).setAll(0, bytes);
      if (bindings.BIO_write(bio, ptr.cast(), bytes.length) != bytes.length) {
        bindings.BIO_free(bio);
        throw OpenSslException('BIO_write failed');
      }
      return bio;
    } finally {
      calloc.free(ptr);
    }
  }

  Uint8List _encode(int Function(Pointer<Pointer<UnsignedChar>>) i2d,
      String function) {
    final len = i2d(nullptr);
    if (len <= 0) {
      throw OpenSslException('$function length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    try {
      out.value = buffer.cast<UnsignedChar>();
      final written = i2d(out);
      if (written <= 0) {
        throw OpenSslException('$function failed');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  Pointer<T> _d2i<T extends NativeType>(
    Uint8List der,
    Arena arena,
    Pointer<T> Function(Pointer<Pointer<UnsignedChar>>, int) d2i,
    String function,
  ) {
    final inPtr = arena<UnsignedChar>(der.length);
    inPtr.cast<Uint8>().asTypedList(der.length).setAll(0, der);
    final inOut = arena<Pointer<UnsignedChar>>();
    inOut.value = inPtr;

    final result = d2i(inOut, der.length);
    if (result == nullptr) {
      throw OpenSslException(
        '$function failed',
        bindings.ERR_get_error(),
        function,
      );
    }
    return result;
  }

  String _drainErrors() {
    final messages = <String>[];
    while (true) {
      final code = bindings.ERR_get_error();
      if (code == 0) break;
      final ptr = bindings.ERR_error_string(code, nullptr);
      if (ptr != nullptr) {
        messages.add(ptr.cast<Utf8>().toDartString());
      }
    }
    return messages.isEmpty ? 'verification failed' : messages.join('; ');
  }

  BigInt? _bigIntFromAsn1(Pointer<ASN1_INTEGER> value) {
    if (value == nullptr) return null;

    final bn = bindings.ASN1_INTEGER_to_BN(value, nullptr);
    if (bn == nullptr) return null;
    try {
      final decPtr = bindings.BN_bn2dec(bn);
      if (decPtr == nullptr) return null;
      try {
        return BigInt.parse(decPtr.cast<Utf8>().toDartString());
      } finally {
        bindings.CRYPTO_free(decPtr.cast(), nullptr, 0);
      }
    } finally {
      bindings.BN_free(bn);
    }
  }
}

/// Builds an `ASN1_INTEGER` from [value].
///
/// Free function because the serial callback runs outside the mixin instance.
Pointer<ASN1_INTEGER> _asn1IntegerFromBigIntWith(
  OpenSslFfi bindings,
  BigInt value,
) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'must not be negative');
  }

  var hex = value.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  final bytes = Uint8List.fromList([
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ]);

  final buffer = calloc<UnsignedChar>(bytes.length);
  try {
    buffer.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);
    final bn = bindings.BN_bin2bn(buffer, bytes.length, nullptr);
    if (bn == nullptr) {
      throw OpenSslException('BN_bin2bn failed');
    }
    try {
      final asn1 = bindings.BN_to_ASN1_INTEGER(bn, nullptr);
      if (asn1 == nullptr) {
        throw OpenSslException('BN_to_ASN1_INTEGER failed');
      }
      return asn1;
    } finally {
      bindings.BN_free(bn);
    }
  } finally {
    calloc.free(buffer);
  }
}
