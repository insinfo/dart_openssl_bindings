import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';
import 'x509_certificate.dart';
import 'x509_crl.dart';
import 'x509_name.dart';

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
    _ensureUsable();

    final revoked = _context.bindings.X509_REVOKED_new();
    if (revoked == nullptr) {
      throw OpenSslException('Failed to create X509_REVOKED');
    }

    final serial = _context.bindings.ASN1_INTEGER_new();
    if (serial == nullptr) {
      _context.bindings.X509_REVOKED_free(revoked);
      throw OpenSslException('Failed to create ASN1_INTEGER');
    }

    final revocation = _createAsn1Time(revocationTime);

    try {
      _context.bindings.ASN1_INTEGER_set(serial, serialNumber);

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

  /// Adds a revoked certificate entry (serial as hex string).
  void addRevokedSerialHex({
    required String serialHex,
    required DateTime revocationTime,
  }) {
    final normalized = serialHex.replaceAll(RegExp(r'^0x', caseSensitive: false), '');
    final value = BigInt.parse(normalized, radix: 16);
    if (value > BigInt.from(0x7FFFFFFF)) {
      throw RangeError('Serial number is too large for ASN1_INTEGER_set');
    }
    addRevokedSerial(serialNumber: value.toInt(), revocationTime: revocationTime);
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
}