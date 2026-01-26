import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';

/// OCSP certificate status.
enum OcspCertStatus {
  good,
  revoked,
  unknown,
}

/// OCSP revocation reason codes (RFC 5280).
enum OcspRevocationReason {
  unspecified,
  keyCompromise,
  cACompromise,
  affiliationChanged,
  superseded,
  cessationOfOperation,
  certificateHold,
  removeFromCrl,
  privilegeWithdrawn,
  aACompromise,
}

/// Single certificate OCSP status payload.
class OcspStatusInfo {
  const OcspStatusInfo({
    required this.status,
    this.revocationTime,
    this.revocationReason,
    this.thisUpdate,
    this.nextUpdate,
  });

  final OcspCertStatus status;
  final DateTime? revocationTime;
  final OcspRevocationReason? revocationReason;
  final DateTime? thisUpdate;
  final DateTime? nextUpdate;
}

/// Builder for OCSP responses (DER).
class OcspResponseBuilder {
  OcspResponseBuilder(this._context);

  final OpenSSL _context;

  /// Builds a DER-encoded OCSP response for the given [requestDer].
  ///
  /// [statusBySerial] is keyed by serial number in decimal string form.
  Uint8List buildDer({
    required Uint8List requestDer,
    required Map<String, OcspStatusInfo> statusBySerial,
    required Pointer<X509> responderCert,
    required EvpPkey responderKey,
    String hashAlgorithm = 'SHA256',
    DateTime? defaultThisUpdate,
    DateTime? defaultNextUpdate,
    bool includeNonce = true,
  }) {
    final bindings = _context.bindings;

    final reqPtr = _d2iOcspRequest(requestDer);
    if (reqPtr == nullptr) {
      throw OpenSslException('Failed to parse OCSP request');
    }

    final basic = bindings.OCSP_BASICRESP_new();
    if (basic == nullptr) {
      bindings.OCSP_REQUEST_free(reqPtr);
      throw OpenSslException('Failed to create OCSP_BASICRESP');
    }

    final now = DateTime.now().toUtc();
    final fallbackThis = defaultThisUpdate ?? now;
    final fallbackNext = defaultNextUpdate ?? now.add(const Duration(hours: 24));

    try {
      if (includeNonce) {
        bindings.OCSP_copy_nonce(basic, reqPtr);
      }

      final count = bindings.OCSP_request_onereq_count(reqPtr);
      for (var i = 0; i < count; i++) {
        final onereq = bindings.OCSP_request_onereq_get0(reqPtr, i);
        if (onereq == nullptr) {
          continue;
        }

        final certId = bindings.OCSP_onereq_get0_id(onereq);
        if (certId == nullptr) {
          continue;
        }

        final serialDecimal = _getSerialDecimal(certId);
        final info = statusBySerial[serialDecimal];

        final status = info?.status ?? OcspCertStatus.unknown;
        final thisUpdate = info?.thisUpdate ?? fallbackThis;
        final nextUpdate = info?.nextUpdate ?? fallbackNext;

        final thisTime = _createAsn1Time(thisUpdate);
        final nextTime = _createAsn1Time(nextUpdate);

        Pointer<ASN1_TIME> revocationTime = nullptr;
        int reason = 0;

        if (status == OcspCertStatus.revoked) {
          final revokeTime = info?.revocationTime ?? now;
          revocationTime = _createAsn1Time(revokeTime);
          reason = _revocationReasonToNative(
            info?.revocationReason ?? OcspRevocationReason.unspecified,
          );
        }

        try {
          final single = bindings.OCSP_basic_add1_status(
            basic,
            certId,
            _statusToNative(status),
            reason,
            revocationTime,
            thisTime,
            nextTime,
          );

          if (single == nullptr) {
            throw OpenSslException('OCSP_basic_add1_status failed');
          }
        } finally {
          bindings.ASN1_TIME_free(thisTime);
          bindings.ASN1_TIME_free(nextTime);
          if (revocationTime != nullptr) {
            bindings.ASN1_TIME_free(revocationTime);
          }
        }
      }

      final md = _getDigestByName(hashAlgorithm);
      final signResult = bindings.OCSP_basic_sign(
        basic,
        responderCert,
        responderKey.handle,
        md,
        nullptr,
        0,
      );
      SslObject.checkCode(
        bindings,
        signResult,
        msg: 'OCSP_basic_sign failed',
      );

      final response = bindings.OCSP_response_create(0, basic);
      if (response == nullptr) {
        throw OpenSslException('OCSP_response_create failed');
      }

      try {
        return _encodeResponse(response);
      } finally {
        bindings.OCSP_RESPONSE_free(response);
      }
    } finally {
      bindings.OCSP_BASICRESP_free(basic);
      bindings.OCSP_REQUEST_free(reqPtr);
    }
  }

  Pointer<OCSP_REQUEST> _d2iOcspRequest(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final inOutPtr = calloc<Pointer<UnsignedChar>>();
    inOutPtr.value = dataPtr.cast<UnsignedChar>();

    try {
      return _context.bindings.d2i_OCSP_REQUEST(nullptr, inOutPtr, der.length);
    } finally {
      calloc.free(inOutPtr);
      calloc.free(dataPtr);
    }
  }

  Uint8List _encodeResponse(Pointer<OCSP_RESPONSE> resp) {
    final len = _context.bindings.i2d_OCSP_RESPONSE(resp, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get OCSP response length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_OCSP_RESPONSE(resp, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode OCSP response');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  Pointer<ASN1_TIME> _createAsn1Time(DateTime time) {
    final ptr = _context.bindings.ASN1_TIME_new();
    if (ptr == nullptr) {
      throw OpenSslException('Failed to create ASN1_TIME');
    }
    final seconds = time.toUtc().millisecondsSinceEpoch ~/ 1000;
    final updated = _context.bindings.ASN1_TIME_set(ptr, seconds);
    if (updated == nullptr) {
      _context.bindings.ASN1_TIME_free(ptr);
      throw OpenSslException('Failed to set ASN1_TIME');
    }
    return ptr;
  }

  Pointer<EVP_MD> _getDigestByName(String name) {
    final cname = name.toNativeUtf8(allocator: calloc);
    try {
      final md = _context.bindings.EVP_get_digestbyname(cname.cast());
      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $name');
      }
      return md;
    } finally {
      calloc.free(cname);
    }
  }

  String _getSerialDecimal(Pointer<OCSP_CERTID> certId) {
    final pSerial = calloc<Pointer<ASN1_INTEGER>>();
    final pNameHash = calloc<Pointer<ASN1_OCTET_STRING>>();
    final pKeyHash = calloc<Pointer<ASN1_OCTET_STRING>>();
    final pMd = calloc<Pointer<ASN1_OBJECT>>();

    try {
      final ok = _context.bindings.OCSP_id_get0_info(
        pNameHash,
        pMd,
        pKeyHash,
        pSerial,
        certId,
      );
      if (ok != 1) {
        return '';
      }
      final serialPtr = pSerial.value;
      if (serialPtr == nullptr) return '';
      return _asn1IntegerToDec(serialPtr);
    } finally {
      calloc.free(pSerial);
      calloc.free(pNameHash);
      calloc.free(pKeyHash);
      calloc.free(pMd);
    }
  }

  String _asn1IntegerToDec(Pointer<ASN1_INTEGER> asn1) {
    final bn = _context.bindings.ASN1_INTEGER_to_BN(asn1, nullptr);
    if (bn == nullptr) return '';
    try {
      final decPtr = _context.bindings.BN_bn2dec(bn);
      if (decPtr == nullptr) return '';
      try {
        return decPtr.cast<Utf8>().toDartString();
      } finally {
        _context.bindings.CRYPTO_free(decPtr.cast(), nullptr, 0);
      }
    } finally {
      _context.bindings.BN_free(bn);
    }
  }

  int _statusToNative(OcspCertStatus status) {
    switch (status) {
      case OcspCertStatus.good:
        return 0; // V_OCSP_CERTSTATUS_GOOD
      case OcspCertStatus.revoked:
        return 1; // V_OCSP_CERTSTATUS_REVOKED
      case OcspCertStatus.unknown:
        return 2; // V_OCSP_CERTSTATUS_UNKNOWN
    }
  }

  int _revocationReasonToNative(OcspRevocationReason reason) {
    switch (reason) {
      case OcspRevocationReason.unspecified:
        return 0;
      case OcspRevocationReason.keyCompromise:
        return 1;
      case OcspRevocationReason.cACompromise:
        return 2;
      case OcspRevocationReason.affiliationChanged:
        return 3;
      case OcspRevocationReason.superseded:
        return 4;
      case OcspRevocationReason.cessationOfOperation:
        return 5;
      case OcspRevocationReason.certificateHold:
        return 6;
      case OcspRevocationReason.removeFromCrl:
        return 8;
      case OcspRevocationReason.privilegeWithdrawn:
        return 9;
      case OcspRevocationReason.aACompromise:
        return 10;
    }
  }
}