import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../api/openssl_context.dart';
import '../infra/ssl_exception.dart';

/// PKI utilities for production-grade operations.
mixin PkiMixin on OpenSslContext {
  /// Generates a cryptographically strong random serial number.
  ///
  /// [bytes] should be between 8 and 20 for production use (RFC 5280).
  BigInt generateSerialNumberBigInt({int bytes = 16}) {
    if (bytes < 8 || bytes > 20) {
      throw RangeError('bytes must be between 8 and 20 for production use');
    }

    final buffer = calloc<UnsignedChar>(bytes);
    try {
      while (true) {
        final ok = bindings.RAND_bytes(buffer, bytes);
        if (ok != 1) {
          throw OpenSslException('RAND_bytes failed');
        }

        final data = buffer.cast<Uint8>().asTypedList(bytes);
        var allZero = true;
        for (final b in data) {
          if (b != 0) {
            allZero = false;
            break;
          }
        }

        if (allZero) {
          continue;
        }

        return _bigIntFromBytes(data);
      }
    } finally {
      calloc.free(buffer);
    }
  }

  BigInt _bigIntFromBytes(Uint8List bytes) {
    var result = BigInt.zero;
    for (final b in bytes) {
      result = (result << 8) | BigInt.from(b);
    }
    return result;
  }
}
