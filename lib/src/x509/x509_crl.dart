import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';
import '../utils/asn1_integer.dart';
import '../utils/asn1_time.dart';
import '../utils/x509_name_text.dart';
import 'x509_certificate.dart';

/// A single entry of a CRL revoked list.
class X509RevokedEntry {
  const X509RevokedEntry({
    required this.serialNumber,
    this.revocationDate,
    this.reasonCode,
  });

  /// Serial number of the revoked certificate.
  final BigInt serialNumber;

  /// When the CA revoked the certificate, in UTC.
  ///
  /// `null` only when OpenSSL cannot parse the entry date.
  final DateTime? revocationDate;

  /// Reason extension (2.5.29.21) as a [CrlReason] value.
  ///
  /// `null` means the entry carries no reason extension, which RFC 5280
  /// treats as `unspecified` — not that the reason is unknown to this API.
  final int? reasonCode;

  /// Serial number as the decimal string the rest of the API takes.
  String get serialNumberDecimal => serialNumber.toString();

  /// Serial number as uppercase hex, the form CAs and viewers print.
  String get serialNumberHex {
    final hex = serialNumber.toRadixString(16).toUpperCase();
    return hex.length.isOdd ? '0$hex' : hex;
  }

  @override
  String toString() => 'X509RevokedEntry(serial: $serialNumberHex, '
      'revokedAt: $revocationDate, reason: $reasonCode)';
}

/// Wrapper around OpenSSL X509_CRL.
class X509Crl extends SslObject<X509_CRL> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  X509Crl(Pointer<X509_CRL> ptr, this._context) : super(ptr) {
    final freePtr =
        _context.lookup<Void Function(Pointer<X509_CRL>)>('X509_CRL_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, ptr.cast(), detach: this);
  }

  void dispose() {
    _finalizer.detach(this);
    _context.bindings.X509_CRL_free(handle);
  }

  /// Issuer DN of this CRL, in the same format as [X509Certificate.issuer].
  String get issuer {
    return x509NameToString(
      _context.bindings,
      _context.bindings.X509_CRL_get_issuer(handle),
    );
  }

  /// CRL version: 1 for v1, 2 for v2 (the encoded value is zero-based).
  int get version => _context.bindings.X509_CRL_get_version(handle) + 1;

  /// CRL number extension (2.5.29.20).
  ///
  /// `null` when the CRL carries no such extension — it is optional for v1
  /// CRLs, and only mandatory for conforming v2 ones.
  BigInt? get crlNumber => _extensionAsBigInt(_oidCrlNumber);

  /// Base CRL number of the delta CRL indicator extension (2.5.29.27).
  ///
  /// `null` when this is a full CRL, which is what [isDeltaCrl] tests.
  BigInt? get baseCrlNumber => _extensionAsBigInt(_oidDeltaCrlIndicator);

  /// Whether this CRL is a delta CRL, i.e. it carries a delta CRL indicator.
  bool get isDeltaCrl => baseCrlNumber != null;

  /// Every revoked entry, in the order the CRL lists them.
  ///
  /// The list is materialised on each call and is empty for a CRL that
  /// revokes nothing. Use [isSerialRevoked] and friends to test a single
  /// serial — that is a lookup in OpenSSL, not a scan of this list.
  List<X509RevokedEntry> get revokedEntries {
    // Borrowed stack owned by the CRL: it must not be freed here.
    final stack = _context.bindings.X509_CRL_get_REVOKED(handle);
    if (stack == nullptr) return const [];

    final entries = <X509RevokedEntry>[];
    final count = _context.bindings.OPENSSL_sk_num(stack.cast());
    for (var i = 0; i < count; i++) {
      final value = _context.bindings.OPENSSL_sk_value(stack.cast(), i);
      if (value == nullptr) continue;

      final revoked = value.cast<X509_REVOKED>();
      final serial = asn1IntegerToBigInt(
        _context.bindings,
        _context.bindings.X509_REVOKED_get0_serialNumber(revoked),
      );
      if (serial == null) continue;

      entries.add(X509RevokedEntry(
        serialNumber: serial,
        revocationDate: parseAsn1Time(
          _context.bindings,
          _context.bindings.X509_REVOKED_get0_revocationDate(revoked),
        ),
        reasonCode: _revocationReason(revoked),
      ));
    }
    return entries;
  }

  static const String _oidCrlNumber = '2.5.29.20';
  static const String _oidDeltaCrlIndicator = '2.5.29.27';
  static const String _oidCrlReason = '2.5.29.21';

  /// Reads an extension whose value is a plain ASN1_INTEGER.
  BigInt? _extensionAsBigInt(String oid) {
    final nid = _objTxtToNid(oid);
    if (nid == 0) return null;

    final extPtr = _context.bindings
        .X509_CRL_get_ext_d2i(handle, nid, nullptr, nullptr)
        .cast<ASN1_INTEGER>();
    if (extPtr == nullptr) return null;

    try {
      return asn1IntegerToBigInt(_context.bindings, extPtr);
    } finally {
      _context.bindings.ASN1_INTEGER_free(extPtr);
    }
  }

  int? _revocationReason(Pointer<X509_REVOKED> revoked) {
    final nid = _objTxtToNid(_oidCrlReason);
    if (nid == 0) return null;

    final reasonPtr = _context.bindings
        .X509_REVOKED_get_ext_d2i(revoked, nid, nullptr, nullptr)
        .cast<ASN1_ENUMERATED>();
    if (reasonPtr == nullptr) return null;

    try {
      return _context.bindings.ASN1_ENUMERATED_get(reasonPtr);
    } finally {
      _context.bindings.ASN1_ENUMERATED_free(reasonPtr);
    }
  }

  int _objTxtToNid(String oid) {
    final oidPtr = oid.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      return _context.bindings.OBJ_txt2nid(oidPtr);
    } finally {
      calloc.free(oidPtr);
    }
  }

  /// Issue date of this CRL (thisUpdate, X509_CRL_get0_lastUpdate).
  ///
  /// Returns `null` when the field cannot be parsed.
  DateTime? get thisUpdate {
    final timePtr = _context.bindings.X509_CRL_get0_lastUpdate(handle);
    return parseAsn1Time(_context.bindings, timePtr);
  }

  /// Date by which the next CRL is expected (nextUpdate).
  ///
  /// The field is optional in RFC 5280, so `null` means the CRL does not
  /// state one — not that it is expired.
  DateTime? get nextUpdate {
    final timePtr = _context.bindings.X509_CRL_get0_nextUpdate(handle);
    return parseAsn1Time(_context.bindings, timePtr);
  }

  /// Whether [reference] (defaults to now) is past [nextUpdate].
  ///
  /// A CRL without a nextUpdate is never reported as expired.
  bool isExpired([DateTime? reference]) {
    final next = nextUpdate;
    if (next == null) return false;
    return (reference?.toUtc() ?? DateTime.now().toUtc()).isAfter(next);
  }

  /// Encodes CRL to PEM.
  String toPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_X509_CRL(bio, handle);
      if (result != 1) {
        throw OpenSslException('Failed to write CRL to PEM');
      }
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }

  /// Encodes CRL to DER bytes.
  Uint8List toDer() {
    final len = _context.bindings.i2d_X509_CRL(handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get CRL DER length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_X509_CRL(handle, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode CRL to DER');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  /// Checks if [serialNumber] appears in this CRL revoked entries.
  bool isSerialRevoked(int serialNumber) {
    if (serialNumber < 0) {
      throw ArgumentError.value(
        serialNumber,
        'serialNumber',
        'Serial number must be non-negative',
      );
    }
    return isSerialRevokedBigInt(BigInt.from(serialNumber));
  }

  /// Checks if decimal [serialNumberDecimal] appears in revoked entries.
  bool isSerialRevokedDecimal(String serialNumberDecimal) {
    final normalized = serialNumberDecimal.trim();
    if (normalized.isEmpty) {
      throw ArgumentError.value(
        serialNumberDecimal,
        'serialNumberDecimal',
        'Serial number cannot be empty',
      );
    }
    return isSerialRevokedBigInt(BigInt.parse(normalized));
  }

  /// Checks if hexadecimal [serialHex] appears in revoked entries.
  bool isSerialRevokedHex(String serialHex) {
    var normalized = serialHex.trim();
    if (normalized.startsWith('0x') || normalized.startsWith('0X')) {
      normalized = normalized.substring(2);
    }
    normalized = normalized.replaceAll(':', '').replaceAll(' ', '');
    if (normalized.isEmpty) {
      throw ArgumentError.value(serialHex, 'serialHex', 'Serial hex is empty');
    }
    return isSerialRevokedBigInt(BigInt.parse(normalized, radix: 16));
  }

  /// Checks if [serialNumber] appears in revoked entries.
  bool isSerialRevokedBigInt(BigInt serialNumber) {
    if (serialNumber < BigInt.zero) {
      throw ArgumentError.value(
        serialNumber,
        'serialNumber',
        'Serial number must be non-negative',
      );
    }

    final serialAsn1 = _asn1IntegerFromBigInt(serialNumber);
    final revokedOut = calloc<Pointer<X509_REVOKED>>();
    try {
      final found = _context.bindings
          .X509_CRL_get0_by_serial(handle, revokedOut, serialAsn1);
      return found == 1;
    } finally {
      _context.bindings.ASN1_INTEGER_free(serialAsn1);
      calloc.free(revokedOut);
    }
  }

  /// Convenience check using certificate serial number.
  bool isCertificateRevoked(X509Certificate certificate) {
    return isSerialRevokedDecimal(certificate.serialNumber);
  }

  Pointer<ASN1_INTEGER> _asn1IntegerFromBigInt(BigInt serialNumber) {
    var hex = serialNumber.toRadixString(16);
    if (hex.length.isOdd) {
      hex = '0$hex';
    }

    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
    }

    final dataPtr = calloc<UnsignedChar>(bytes.length);
    dataPtr.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);

    try {
      final bn = _context.bindings.BN_bin2bn(dataPtr, bytes.length, nullptr);
      if (bn == nullptr) {
        throw OpenSslException('BN_bin2bn failed for CRL serial check');
      }
      try {
        final asn1 = _context.bindings.BN_to_ASN1_INTEGER(bn, nullptr);
        if (asn1 == nullptr) {
          throw OpenSslException(
              'BN_to_ASN1_INTEGER failed for CRL serial check');
        }
        return asn1;
      } finally {
        _context.bindings.BN_free(bn);
      }
    } finally {
      calloc.free(dataPtr);
    }
  }
}
