import 'dart:io';
import 'dart:typed_data';

/// Formats the raw octets of an X.509 iPAddress as text: dotted quad for the
/// 4 byte form, canonical colon-hex for the 16 byte one.
///
/// Returns `null` for any other length, which is what a malformed extension
/// looks like — RFC 5280 allows only those two.
String? ipBytesToText(Uint8List bytes) {
  if (bytes.length != 4 && bytes.length != 16) return null;
  try {
    return InternetAddress.fromRawAddress(bytes).address;
  } on ArgumentError {
    return null;
  }
}
