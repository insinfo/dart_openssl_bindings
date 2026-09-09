import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../generated/ffi.dart';

/// Reads an ASN1_INTEGER as a decimal string.
///
/// Returns `null` for `nullptr` or when OpenSSL cannot convert the value,
/// which keeps optional fields (a CRL number that is not there) distinct from
/// a serial that really is zero.
String? asn1IntegerToDecimalString(
  OpenSslFfi bindings,
  Pointer<ASN1_INTEGER> asn1Int,
) {
  if (asn1Int == nullptr) return null;

  final bn = bindings.ASN1_INTEGER_to_BN(asn1Int, nullptr);
  if (bn == nullptr) return null;

  try {
    final decPtr = bindings.BN_bn2dec(bn);
    if (decPtr == nullptr) return null;
    try {
      return decPtr.cast<Utf8>().toDartString();
    } finally {
      // Safe to call CRYPTO_free on OpenSSL allocated strings.
      bindings.CRYPTO_free(decPtr.cast(), nullptr, 0);
    }
  } finally {
    bindings.BN_free(bn);
  }
}

/// Reads an ASN1_INTEGER as a [BigInt], so serials wider than 64 bits survive.
///
/// Returns `null` under the same conditions as [asn1IntegerToDecimalString].
BigInt? asn1IntegerToBigInt(
  OpenSslFfi bindings,
  Pointer<ASN1_INTEGER> asn1Int,
) {
  final decimal = asn1IntegerToDecimalString(bindings, asn1Int);
  if (decimal == null || decimal.isEmpty) return null;
  return BigInt.tryParse(decimal);
}
