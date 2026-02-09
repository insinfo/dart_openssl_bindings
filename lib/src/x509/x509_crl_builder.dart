import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';
import 'x509_certificate.dart';
import 'x509_crl.dart';
import 'x509_name.dart';

/// CRL reason codes (RFC 5280).
class CrlReason {
  static const int unspecified = 0;
  static const int keyCompromise = 1;
  static const int caCompromise = 2;
  static const int affiliationChanged = 3;
  static const int superseded = 4;
  static const int cessationOfOperation = 5;
  static const int certificateHold = 6;
  static const int removeFromCrl = 8;
  static const int privilegeWithdrawn = 9;
  static const int aaCompromise = 10;

  const CrlReason._();
}

/// Builder for X509 CRLs.
class X509CrlBuilder implements Finalizable {
  final OpenSSL _context;
  final Pointer<X509_CRL> _crl;
  late final NativeFinalizer _finalizer;
  bool _isDisposed = false;
  bool _isSigned = false;

  X509CrlBuilder(this._context) : _crl = _context.bindings.X509_CRL_new() {
    if (_crl == nullptr) {
      throw OpenSslException('Failed to create X509_CRL structure');
    }
    final freePtr =
        _context.lookup<Void Function(Pointer<X509_CRL>)>('X509_CRL_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, _crl.cast(), detach: this);

    // CRL v2 is version 1 (zero-based).
    SslObject.checkCode(
      _context.bindings,
      _context.bindings.X509_CRL_set_version(_crl, 1),
      msg: 'Failed to set CRL version',
    );
  }

  void _ensureUsable() {
    if (_isDisposed) {
      throw StateError('X509CrlBuilder has been disposed');
    }
    if (_isSigned) {
      throw StateError('X509CrlBuilder already signed');
    }
  }

  /// Sets issuer name from certificate subject.
  void setIssuerFromCertificate(X509Certificate issuerCert) {
    _ensureUsable();
    final issuerName =
        _context.bindings.X509_get_subject_name(issuerCert.handle);
    SslObject.checkCode(
      _context.bindings,
      _context.bindings.X509_CRL_set_issuer_name(_crl, issuerName),
      msg: 'Failed to set CRL issuer name from certificate',
    );
  }

  /// Sets issuer name from attributes.
  void setIssuerName({
    String? commonName,
    String? organization,
    String? country,
    String? locality,
    String? state,
    String? unit,
  }) {
    _ensureUsable();

    final namePtr = _context.bindings.X509_NAME_new();
    if (namePtr == nullptr) {
      throw OpenSslException('Failed to create X509_NAME');
    }
    final name = X509Name(namePtr, _context, isOwned: true);
    try {
      if (commonName != null) name.addEntry('CN', commonName);
      if (organization != null) name.addEntry('O', organization);
      if (country != null) name.addEntry('C', country);
      if (locality != null) name.addEntry('L', locality);
      if (state != null) name.addEntry('ST', state);
      if (unit != null) name.addEntry('OU', unit);

      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_set_issuer_name(_crl, name.handle),
        msg: 'Failed to set CRL issuer name',
      );
    } finally {
      name.dispose();
    }
  }

  /// Sets lastUpdate (thisUpdate) and nextUpdate.
  void setUpdateTimes({
    required DateTime thisUpdate,
    required DateTime nextUpdate,
  }) {
    _ensureUsable();
    final thisTime = _createAsn1Time(thisUpdate);
    final nextTime = _createAsn1Time(nextUpdate);

    try {
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_set1_lastUpdate(_crl, thisTime),
        msg: 'Failed to set CRL lastUpdate',
      );
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_set1_nextUpdate(_crl, nextTime),
        msg: 'Failed to set CRL nextUpdate',
      );
    } finally {
      _context.bindings.ASN1_TIME_free(thisTime);
      _context.bindings.ASN1_TIME_free(nextTime);
    }
  }

  /// Adds a revoked certificate entry (serial as int).
  void addRevokedSerial({
    required int serialNumber,
    required DateTime revocationTime,
  }) {
    _addRevokedSerialInternal(
      serial: _asn1IntegerFromInt(serialNumber),
      revocationTime: revocationTime,
    );
  }

  /// Adds a revoked certificate entry (serial as BigInt).
  void addRevokedSerialBigInt({
    required BigInt serialNumber,
    required DateTime revocationTime,
  }) {
    _addRevokedSerialInternal(
      serial: _asn1IntegerFromBigInt(serialNumber),
      revocationTime: revocationTime,
    );
  }

  void _addRevokedSerialInternal({
    required Pointer<ASN1_INTEGER> serial,
    required DateTime revocationTime,
  }) {
    _ensureUsable();

    final revoked = _context.bindings.X509_REVOKED_new();
    if (revoked == nullptr) {
      throw OpenSslException('Failed to create X509_REVOKED');
    }

    final revocation = _createAsn1Time(revocationTime);

    try {
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_REVOKED_set_serialNumber(revoked, serial),
        msg: 'Failed to set revoked serial number',
      );
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_REVOKED_set_revocationDate(revoked, revocation),
        msg: 'Failed to set revoked date',
      );

      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_add0_revoked(_crl, revoked),
        msg: 'Failed to add revoked entry to CRL',
      );
    } catch (_) {
      _context.bindings.X509_REVOKED_free(revoked);
      rethrow;
    } finally {
      _context.bindings.ASN1_INTEGER_free(serial);
      _context.bindings.ASN1_TIME_free(revocation);
    }
  }

  /// Adds a revoked certificate entry with CRL reason.
  void addRevokedSerialWithReason({
    required int serialNumber,
    required DateTime revocationTime,
    required int reasonCode,
    bool critical = false,
  }) {
    _addRevokedSerialWithReasonInternal(
      serial: _asn1IntegerFromInt(serialNumber),
      revocationTime: revocationTime,
      reasonCode: reasonCode,
      critical: critical,
    );
  }

  /// Adds a revoked certificate entry with CRL reason (serial as BigInt).
  void addRevokedSerialWithReasonBigInt({
    required BigInt serialNumber,
    required DateTime revocationTime,
    required int reasonCode,
    bool critical = false,
  }) {
    _addRevokedSerialWithReasonInternal(
      serial: _asn1IntegerFromBigInt(serialNumber),
      revocationTime: revocationTime,
      reasonCode: reasonCode,
      critical: critical,
    );
  }

  void _addRevokedSerialWithReasonInternal({
    required Pointer<ASN1_INTEGER> serial,
    required DateTime revocationTime,
    required int reasonCode,
    required bool critical,
  }) {
    _ensureUsable();

    final revoked = _context.bindings.X509_REVOKED_new();
    if (revoked == nullptr) {
      throw OpenSslException('Failed to create X509_REVOKED');
    }

    final revocation = _createAsn1Time(revocationTime);

    Pointer<ASN1_ENUMERATED> reason = nullptr;
    try {
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_REVOKED_set_serialNumber(revoked, serial),
        msg: 'Failed to set revoked serial number',
      );
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_REVOKED_set_revocationDate(revoked, revocation),
        msg: 'Failed to set revoked date',
      );

      reason = _context.bindings.ASN1_ENUMERATED_new();
      if (reason == nullptr) {
        throw OpenSslException('Failed to create ASN1_ENUMERATED');
      }
      if (_context.bindings.ASN1_ENUMERATED_set(reason, reasonCode) != 1) {
        throw OpenSslException('Failed to set CRL reason code');
      }

      final nid = _getNid(['crlReason', 'CRLReason', '2.5.29.21']);
      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_REVOKED_add1_ext_i2d(
          revoked,
          nid,
          reason.cast(),
          critical ? 1 : 0,
          0,
        ),
        msg: 'Failed to add CRL reason extension',
      );

      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_add0_revoked(_crl, revoked),
        msg: 'Failed to add revoked entry to CRL',
      );
    } catch (_) {
      _context.bindings.X509_REVOKED_free(revoked);
      rethrow;
    } finally {
      if (reason != nullptr) {
        _context.bindings.ASN1_ENUMERATED_free(reason);
      }
      _context.bindings.ASN1_INTEGER_free(serial);
      _context.bindings.ASN1_TIME_free(revocation);
    }
  }

  /// Adds a revoked certificate entry (serial as hex string).
  void addRevokedSerialHex({
    required String serialHex,
    required DateTime revocationTime,
  }) {
    final normalized =
        serialHex.replaceAll(RegExp(r'^0x', caseSensitive: false), '');
    final value = BigInt.parse(normalized, radix: 16);
    addRevokedSerialBigInt(serialNumber: value, revocationTime: revocationTime);
  }

  /// Sets CRL Number extension (RFC 5280).
  void setCrlNumber({required int number, bool critical = false}) {
    _setCrlNumberInternal(
      numberAsn1: _asn1IntegerFromInt(number),
      critical: critical,
    );
  }

  /// Sets CRL Number extension (RFC 5280) using BigInt.
  void setCrlNumberBigInt({required BigInt number, bool critical = false}) {
    _setCrlNumberInternal(
      numberAsn1: _asn1IntegerFromBigInt(number),
      critical: critical,
    );
  }

  void _setCrlNumberInternal({
    required Pointer<ASN1_INTEGER> numberAsn1,
    required bool critical,
  }) {
    _ensureUsable();

    try {
      final nid = _getNid(['crlNumber', 'CRLNumber', '2.5.29.20']);

      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_add1_ext_i2d(
          _crl,
          nid,
          numberAsn1.cast(),
          critical ? 1 : 0,
          0,
        ),
        msg: 'Failed to add CRL number extension',
      );
    } finally {
      _context.bindings.ASN1_INTEGER_free(numberAsn1);
    }
  }

  /// Sets Delta CRL indicator (RFC 5280) referencing base CRL number.
  void setDeltaCrlIndicator(
      {required int baseCrlNumber, bool critical = true}) {
    _setDeltaCrlIndicatorInternal(
      baseCrlNumberAsn1: _asn1IntegerFromInt(baseCrlNumber),
      critical: critical,
    );
  }

  /// Sets Delta CRL indicator (RFC 5280) using BigInt base CRL number.
  void setDeltaCrlIndicatorBigInt({
    required BigInt baseCrlNumber,
    bool critical = true,
  }) {
    _setDeltaCrlIndicatorInternal(
      baseCrlNumberAsn1: _asn1IntegerFromBigInt(baseCrlNumber),
      critical: critical,
    );
  }

  void _setDeltaCrlIndicatorInternal({
    required Pointer<ASN1_INTEGER> baseCrlNumberAsn1,
    required bool critical,
  }) {
    _ensureUsable();

    try {
      final nid = _getNid(['deltaCRL', 'deltaCRLIndicator', '2.5.29.27']);

      SslObject.checkCode(
        _context.bindings,
        _context.bindings.X509_CRL_add1_ext_i2d(
          _crl,
          nid,
          baseCrlNumberAsn1.cast(),
          critical ? 1 : 0,
          0,
        ),
        msg: 'Failed to add Delta CRL indicator',
      );
    } finally {
      _context.bindings.ASN1_INTEGER_free(baseCrlNumberAsn1);
    }
  }

  /// Adds Authority Key Identifier extension to the CRL using issuer cert.
  void setAuthorityKeyIdentifierFromIssuer({
    required X509Certificate issuerCert,
    bool critical = false,
  }) {
    _ensureUsable();

    final arena = Arena();
    Pointer<X509_EXTENSION> ext = nullptr;
    Pointer<EVP_PKEY> issuerPkey = nullptr;
    try {
      final ctx = arena<X509V3_CTX>();
      _context.bindings.X509V3_set_ctx(
        ctx,
        issuerCert.handle,
        issuerCert.handle,
        nullptr,
        _crl,
        0,
      );
      ctx.ref.db = nullptr;
      ctx.ref.db_meth = nullptr;
      issuerPkey = _context.bindings.X509_get_pubkey(issuerCert.handle);
      if (issuerPkey != nullptr) {
        ctx.ref.issuer_pkey = issuerPkey;
      }

      final nid = _getNid(['authorityKeyIdentifier', '2.5.29.35']);
      final namePtr = 'authorityKeyIdentifier'.toNativeUtf8(allocator: arena);
      final candidates = <String>[
        'keyid:always,issuer:always',
        'keyid:always',
        'keyid',
        'issuer:always',
        'issuer',
      ];

      for (final candidate in candidates) {
        final value = critical ? 'critical,$candidate' : candidate;
        final valuePtr = value.toNativeUtf8(allocator: arena);
        ext = _context.bindings.X509V3_EXT_conf_nid(
          nullptr,
          ctx,
          nid,
          valuePtr.cast(),
        );
        if (ext == nullptr) {
          ext = _context.bindings.X509V3_EXT_nconf(
            nullptr,
            ctx,
            namePtr.cast(),
            valuePtr.cast(),
          );
        }
        if (ext != nullptr) {
          break;
        }
      }

      if (ext == nullptr) {
        throw OpenSslException('Failed to create authorityKeyIdentifier');
      }

      if (_context.bindings.X509_CRL_add_ext(_crl, ext, -1) != 1) {
        throw OpenSslException('Failed to add authorityKeyIdentifier');
      }
    } finally {
      if (ext != nullptr) {
        _context.bindings.X509_EXTENSION_free(ext);
      }
      if (issuerPkey != nullptr) {
        _context.bindings.EVP_PKEY_free(issuerPkey);
      }
      arena.releaseAll();
    }
  }

  /// Signs the CRL and returns a managed wrapper.
  X509Crl sign({
    required EvpPkey issuerKey,
    String hashAlgorithm = 'SHA256',
  }) {
    _ensureUsable();

    final digestName = hashAlgorithm.toNativeUtf8(allocator: calloc);
    try {
      final md = _context.bindings.EVP_get_digestbyname(digestName.cast());
      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $hashAlgorithm');
      }

      _context.bindings.X509_CRL_sort(_crl);

      final result = _context.bindings.X509_CRL_sign(
        _crl,
        issuerKey.handle,
        md,
      );

      SslObject.checkCode(
        _context.bindings,
        result,
        msg: 'Failed to sign CRL',
      );

      _finalizer.detach(this);
      _isSigned = true;
      return X509Crl(_crl, _context);
    } finally {
      calloc.free(digestName);
    }
  }

  int _getNid(List<String> names) {
    for (final name in names) {
      final namePtr = name.toNativeUtf8(allocator: calloc);
      try {
        final nid = _context.bindings.OBJ_txt2nid(namePtr.cast());
        if (nid > 0) {
          return nid;
        }
      } finally {
        calloc.free(namePtr);
      }
    }
    throw OpenSslException('Unknown NID for: ${names.join(", ")}');
  }

  /// Releases native resources.
  void dispose() {
    if (_isDisposed || _isSigned) return;
    _isDisposed = true;
    _finalizer.detach(this);
    _context.bindings.X509_CRL_free(_crl);
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

  Pointer<ASN1_INTEGER> _asn1IntegerFromInt(int value) {
    final asn1 = _context.bindings.ASN1_INTEGER_new();
    if (asn1 == nullptr) {
      throw OpenSslException('Failed to create ASN1_INTEGER');
    }
    if (_context.bindings.ASN1_INTEGER_set(asn1, value) != 1) {
      _context.bindings.ASN1_INTEGER_free(asn1);
      throw OpenSslException('Failed to set ASN1_INTEGER');
    }
    return asn1;
  }

  Pointer<ASN1_INTEGER> _asn1IntegerFromBigInt(BigInt value) {
    if (value <= BigInt.zero) {
      throw RangeError('Serial number must be positive');
    }

    final bytes = _bigIntToBytes(value);
    final bytesPtr = calloc<UnsignedChar>(bytes.length);
    try {
      bytesPtr.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);
      final bn = _context.bindings.BN_bin2bn(bytesPtr, bytes.length, nullptr);
      if (bn == nullptr) {
        throw OpenSslException('BN_bin2bn failed');
      }
      try {
        final asn1 = _context.bindings.BN_to_ASN1_INTEGER(bn, nullptr);
        if (asn1 == nullptr) {
          throw OpenSslException('BN_to_ASN1_INTEGER failed');
        }
        return asn1;
      } finally {
        _context.bindings.BN_free(bn);
      }
    } finally {
      calloc.free(bytesPtr);
    }
  }

  Uint8List _bigIntToBytes(BigInt value) {
    var hex = value.toRadixString(16);
    if (hex.length.isOdd) {
      hex = '0$hex';
    }

    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
    }
    return bytes;
  }
}
