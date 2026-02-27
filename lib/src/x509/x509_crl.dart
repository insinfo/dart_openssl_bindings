import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';
import 'x509_certificate.dart';

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
