import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../utils/tm_unix.dart';
import '../utils/tm_windows.dart';
import 'ocsp_response_builder.dart';

/// Parsed OCSP status for a single certificate in a response.
class OcspCertificateStatusResult {
  const OcspCertificateStatusResult({
    required this.responseStatusCode,
    required this.status,
    this.revocationReason,
    this.revocationTime,
    this.thisUpdate,
    this.nextUpdate,
  });

  /// OCSP response status code (0 means successful).
  final int responseStatusCode;

  /// Certificate status from the OCSP single response.
  final OcspCertStatus status;

  /// Optional revocation reason when status is revoked.
  final OcspRevocationReason? revocationReason;

  /// Optional revocation time when status is revoked.
  final DateTime? revocationTime;

  /// thisUpdate from the OCSP single response.
  final DateTime? thisUpdate;

  /// nextUpdate from the OCSP single response.
  final DateTime? nextUpdate;

  /// Convenience flag for response-level status.
  bool get isResponseSuccessful => responseStatusCode == 0;
}

/// OCSP client-side helper:
/// - builds OCSP requests (DER)
/// - reads OCSP responses (DER) for a specific certificate.
class OcspClient {
  OcspClient(this._context);

  final OpenSSL _context;

  /// Builds a DER-encoded OCSP request for [certificate]/[issuerCertificate].
  ///
  /// [hashAlgorithm] defaults to SHA1 to match OpenSSL CLI behavior.
  /// Set [nonceLength] > 0 to include a nonce.
  Uint8List buildRequestDer({
    required Pointer<X509> certificate,
    required Pointer<X509> issuerCertificate,
    String hashAlgorithm = 'SHA1',
    int? nonceLength,
  }) {
    final bindings = _context.bindings;

    final request = bindings.OCSP_REQUEST_new();
    if (request == nullptr) {
      throw OpenSslException('Failed to create OCSP request');
    }

    try {
      final digest = _getDigestByName(hashAlgorithm);
      final certId = bindings.OCSP_cert_to_id(
        digest,
        certificate,
        issuerCertificate,
      );
      if (certId == nullptr) {
        throw OpenSslException('Failed to create OCSP cert id');
      }

      final oneReq = bindings.OCSP_request_add0_id(request, certId);
      if (oneReq == nullptr) {
        bindings.OCSP_CERTID_free(certId);
        throw OpenSslException('Failed to add cert id to OCSP request');
      }

      if (nonceLength != null && nonceLength > 0) {
        final nonce = calloc<UnsignedChar>(nonceLength);
        try {
          if (bindings.RAND_bytes(nonce, nonceLength) != 1) {
            throw OpenSslException('Failed to generate OCSP nonce');
          }
          if (bindings.OCSP_request_add1_nonce(request, nonce, nonceLength) !=
              1) {
            throw OpenSslException('Failed to add OCSP nonce');
          }
        } finally {
          calloc.free(nonce);
        }
      }

      return _encodeRequest(request);
    } finally {
      bindings.OCSP_REQUEST_free(request);
    }
  }

  /// Parses [responseDer] and extracts status for [certificate]/[issuerCertificate].
  ///
  /// Throws [OpenSslException] if response is malformed, unsuccessful, or does
  /// not contain status for the target certificate.
  OcspCertificateStatusResult readResponseStatus({
    required Uint8List responseDer,
    required Pointer<X509> certificate,
    required Pointer<X509> issuerCertificate,
    String hashAlgorithm = 'SHA1',
    bool requireSuccessfulResponse = true,
  }) {
    final bindings = _context.bindings;
    final response = _d2iOcspResponse(responseDer);
    if (response == nullptr) {
      throw OpenSslException('Failed to parse OCSP response');
    }

    try {
      final responseStatus = bindings.OCSP_response_status(response);
      if (requireSuccessfulResponse && responseStatus != 0) {
        throw OpenSslException(
          'OCSP response status is not successful: $responseStatus',
        );
      }

      final basic = bindings.OCSP_response_get1_basic(response);
      if (basic == nullptr) {
        throw OpenSslException('Failed to extract OCSP basic response');
      }

      try {
        final digest = _getDigestByName(hashAlgorithm);
        final certId = bindings.OCSP_cert_to_id(
          digest,
          certificate,
          issuerCertificate,
        );
        if (certId == nullptr) {
          throw OpenSslException('Failed to create OCSP cert id');
        }

        try {
          final status = calloc<Int>();
          final reason = calloc<Int>();
          final revTime = calloc<Pointer<ASN1_GENERALIZEDTIME>>();
          final thisUpd = calloc<Pointer<ASN1_GENERALIZEDTIME>>();
          final nextUpd = calloc<Pointer<ASN1_GENERALIZEDTIME>>();

          try {
            final found = bindings.OCSP_resp_find_status(
              basic,
              certId,
              status,
              reason,
              revTime,
              thisUpd,
              nextUpd,
            );
            if (found != 1) {
              throw OpenSslException(
                'OCSP response does not contain status for certificate',
              );
            }

            final parsedStatus = _statusFromNative(status.value);
            final parsedReason = parsedStatus == OcspCertStatus.revoked
                ? _reasonFromNative(reason.value)
                : null;

            return OcspCertificateStatusResult(
              responseStatusCode: responseStatus,
              status: parsedStatus,
              revocationReason: parsedReason,
              revocationTime: _parseGeneralizedTime(revTime.value),
              thisUpdate: _parseGeneralizedTime(thisUpd.value),
              nextUpdate: _parseGeneralizedTime(nextUpd.value),
            );
          } finally {
            calloc.free(nextUpd);
            calloc.free(thisUpd);
            calloc.free(revTime);
            calloc.free(reason);
            calloc.free(status);
          }
        } finally {
          bindings.OCSP_CERTID_free(certId);
        }
      } finally {
        bindings.OCSP_BASICRESP_free(basic);
      }
    } finally {
      bindings.OCSP_RESPONSE_free(response);
    }
  }

  Uint8List _encodeRequest(Pointer<OCSP_REQUEST> request) {
    final len = _context.bindings.i2d_OCSP_REQUEST(request, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get OCSP request length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_OCSP_REQUEST(request, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode OCSP request');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  Pointer<OCSP_RESPONSE> _d2iOcspResponse(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final inOutPtr = calloc<Pointer<UnsignedChar>>();
    inOutPtr.value = dataPtr.cast<UnsignedChar>();

    try {
      return _context.bindings.d2i_OCSP_RESPONSE(nullptr, inOutPtr, der.length);
    } finally {
      calloc.free(inOutPtr);
      calloc.free(dataPtr);
    }
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

  OcspCertStatus _statusFromNative(int status) {
    switch (status) {
      case 0:
        return OcspCertStatus.good;
      case 1:
        return OcspCertStatus.revoked;
      case 2:
        return OcspCertStatus.unknown;
      default:
        throw OpenSslException('Unknown OCSP certificate status: $status');
    }
  }

  OcspRevocationReason? _reasonFromNative(int reason) {
    switch (reason) {
      case 0:
        return OcspRevocationReason.unspecified;
      case 1:
        return OcspRevocationReason.keyCompromise;
      case 2:
        return OcspRevocationReason.cACompromise;
      case 3:
        return OcspRevocationReason.affiliationChanged;
      case 4:
        return OcspRevocationReason.superseded;
      case 5:
        return OcspRevocationReason.cessationOfOperation;
      case 6:
        return OcspRevocationReason.certificateHold;
      case 8:
        return OcspRevocationReason.removeFromCrl;
      case 9:
        return OcspRevocationReason.privilegeWithdrawn;
      case 10:
        return OcspRevocationReason.aACompromise;
      default:
        return null;
    }
  }

  int _tmNativeBytes() {
    if (Platform.isWindows) return sizeOf<TmWindows>();
    return sizeOf<TmUnix>();
  }

  Pointer<tm> _allocTmCompat() {
    final raw = calloc<Uint8>(_tmNativeBytes());
    return raw.cast<tm>();
  }

  void _freeTmCompat(Pointer<tm> tmPtr) {
    calloc.free(tmPtr.cast<Uint8>());
  }

  DateTime? _parseGeneralizedTime(Pointer<ASN1_GENERALIZEDTIME> ptr) {
    if (ptr == nullptr) return null;
    final tmPtr = _allocTmCompat();
    try {
      final ok = _context.bindings.ASN1_TIME_to_tm(
        ptr.cast<ASN1_TIME>(),
        tmPtr,
      );
      if (ok != 1) return null;

      final t = tmPtr.ref;
      return DateTime.utc(
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
      );
    } finally {
      _freeTmCompat(tmPtr);
    }
  }
}
