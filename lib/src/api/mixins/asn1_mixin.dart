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

  /// Extract issuer name (DER) and serial number (DER) from a certificate DER.
  ({Uint8List issuerDer, Uint8List serialDer})
      extractIssuerAndSerialDer(Uint8List certificateDer) {
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
}
