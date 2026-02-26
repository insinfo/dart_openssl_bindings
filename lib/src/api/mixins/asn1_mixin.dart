import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../../infra/ssl_exception.dart';
import '../../x509/x509_certificate.dart';
import '../../generated/ffi.dart';

/// Mixin for high-level ASN.1 helpers using OpenSSL's ASN.1 APIs.
mixin Asn1Mixin on OpenSslContext {
  /// Decode a DER-encoded X509 certificate to an [X509Certificate] wrapper.
  X509Certificate loadCertificateDer(Uint8List der) {
    final certPtr = _d2iX509(der);
    return X509Certificate(certPtr, this as dynamic);
  }

  /// Encode an X509 certificate to DER.
  Uint8List encodeX509(X509Certificate cert) {
    return _i2dToBytes(
      (out) => bindings.i2d_X509(cert.handle, out),
    );
  }

  /// Encode an X509_NAME to DER.
  Uint8List encodeX509Name(Pointer<X509_NAME> name) {
    return _i2dToBytes(
      (out) => bindings.i2d_X509_NAME(name, out),
    );
  }

  /// Encode an ASN1_INTEGER to DER.
  Uint8List encodeAsn1Integer(Pointer<ASN1_INTEGER> integer) {
    return _i2dToBytes(
      (out) => bindings.i2d_ASN1_INTEGER(integer, out),
    );
  }

  /// Reads certificate serial bytes directly from ASN1_INTEGER payload.
  ///
  /// This preserves full serial bytes without truncation.
  Uint8List x509GetSerialBytes(Pointer<X509> cert) {
    final serial = bindings.X509_get_serialNumber(cert);
    if (serial == nullptr) {
      throw OpenSslException('X509_get_serialNumber failed');
    }

    final len = bindings.ASN1_STRING_length(serial.cast());
    if (len < 0) {
      throw OpenSslException('ASN1_STRING_length failed for serial');
    }

    if (len == 0) {
      return Uint8List(0);
    }

    final data = bindings.ASN1_STRING_get0_data(serial.cast());
    if (data == nullptr) {
      throw OpenSslException('ASN1_STRING_get0_data failed for serial');
    }

    return Uint8List.fromList(data.cast<Uint8>().asTypedList(len));
  }

  /// Gets certificate serial as hexadecimal string.
  String x509GetSerialHex(Pointer<X509> cert, {bool prefixed = true}) {
    final bytes = x509GetSerialBytes(cert);
    final hex = _bytesToHex(bytes);
    return prefixed ? '0x$hex' : hex;
  }

  /// Gets certificate serial as decimal string using BIGNUM conversion.
  String x509GetSerialDecimal(Pointer<X509> cert) {
    final serial = bindings.X509_get_serialNumber(cert);
    if (serial == nullptr) {
      throw OpenSslException('X509_get_serialNumber failed');
    }
    return asn1IntegerToDecimal(serial);
  }

  /// Converts ASN1_INTEGER to hexadecimal string via BIGNUM.
  String asn1IntegerToHex(Pointer<ASN1_INTEGER> value) {
    final bn = bindings.ASN1_INTEGER_to_BN(value, nullptr);
    if (bn == nullptr) {
      throw OpenSslException('ASN1_INTEGER_to_BN failed');
    }

    try {
      final hexPtr = bindings.BN_bn2hex(bn);
      if (hexPtr == nullptr) {
        throw OpenSslException('BN_bn2hex failed');
      }
      try {
        return hexPtr.cast<Utf8>().toDartString();
      } finally {
        bindings.CRYPTO_free(hexPtr.cast(), nullptr, 0);
      }
    } finally {
      bindings.BN_free(bn);
    }
  }

  /// Converts ASN1_INTEGER to decimal string via BIGNUM.
  String asn1IntegerToDecimal(Pointer<ASN1_INTEGER> value) {
    final bn = bindings.ASN1_INTEGER_to_BN(value, nullptr);
    if (bn == nullptr) {
      throw OpenSslException('ASN1_INTEGER_to_BN failed');
    }

    try {
      final decPtr = bindings.BN_bn2dec(bn);
      if (decPtr == nullptr) {
        throw OpenSslException('BN_bn2dec failed');
      }
      try {
        return decPtr.cast<Utf8>().toDartString();
      } finally {
        bindings.CRYPTO_free(decPtr.cast(), nullptr, 0);
      }
    } finally {
      bindings.BN_free(bn);
    }
  }

  /// Converts hexadecimal string to ASN1_INTEGER through BIGNUM.
  ///
  /// Caller is responsible for freeing the returned pointer using
  /// `ASN1_INTEGER_free`.
  Pointer<ASN1_INTEGER> asn1IntegerFromHex(String hex) {
    var normalized = hex.trim();
    if (normalized.startsWith('0x') || normalized.startsWith('0X')) {
      normalized = normalized.substring(2);
    }
    normalized = normalized.replaceAll(':', '').replaceAll(' ', '');
    if (normalized.isEmpty || !_isHex(normalized)) {
      throw ArgumentError('Invalid hexadecimal ASN1 integer: $hex');
    }

    if (normalized.length.isOdd) {
      normalized = '0$normalized';
    }

    final bytes = _hexToBytes(normalized);
    final inPtr = calloc<Uint8>(bytes.length);
    inPtr.asTypedList(bytes.length).setAll(0, bytes);

    final bn =
        bindings.BN_bin2bn(inPtr.cast<UnsignedChar>(), bytes.length, nullptr);
    calloc.free(inPtr);

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
  }

  /// Extract issuer name (DER) and serial number (DER) from a certificate DER.
  ({Uint8List issuerDer, Uint8List serialDer}) extractIssuerAndSerialDer(
      Uint8List certificateDer) {
    final certPtr = _d2iX509(certificateDer);
    try {
      final issuerName = bindings.X509_get_issuer_name(certPtr);
      if (issuerName == nullptr) {
        throw OpenSslException('X509_get_issuer_name failed');
      }

      final serial = bindings.X509_get_serialNumber(certPtr);
      if (serial == nullptr) {
        throw OpenSslException('X509_get_serialNumber failed');
      }

      return (
        issuerDer: encodeX509Name(issuerName),
        serialDer: encodeAsn1Integer(serial),
      );
    } finally {
      bindings.X509_free(certPtr);
    }
  }

  Pointer<X509> _d2iX509(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final pp = calloc<Pointer<UnsignedChar>>();
    pp.value = dataPtr.cast<UnsignedChar>();

    final cert = bindings.d2i_X509(nullptr, pp, der.length);

    calloc.free(pp);
    calloc.free(dataPtr);

    if (cert == nullptr) {
      throw OpenSslException('d2i_X509 failed');
    }

    return cert;
  }

  Uint8List _i2dToBytes(
      int Function(Pointer<Pointer<UnsignedChar>> out) encoder) {
    final len = encoder(nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_* length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    final written = encoder(out);
    calloc.free(out);

    if (written <= 0) {
      calloc.free(buffer);
      throw OpenSslException('i2d_* encode failed');
    }

    final bytes = Uint8List.fromList(buffer.asTypedList(written));
    calloc.free(buffer);
    return bytes;
  }

  String _bytesToHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  bool _isHex(String value) {
    for (final codeUnit in value.codeUnits) {
      final isDigit = codeUnit >= 48 && codeUnit <= 57;
      final isUpper = codeUnit >= 65 && codeUnit <= 70;
      final isLower = codeUnit >= 97 && codeUnit <= 102;
      if (!isDigit && !isUpper && !isLower) {
        return false;
      }
    }
    return true;
  }

  Uint8List _hexToBytes(String hex) {
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      final idx = i * 2;
      out[i] = int.parse(hex.substring(idx, idx + 2), radix: 16);
    }
    return out;
  }
}
