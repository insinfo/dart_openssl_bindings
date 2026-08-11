import 'dart:typed_data';

/// Encodes [bytes] as lowercase hexadecimal.
///
/// This file is deliberately kept out of the `openssl.dart` barrel, like the
/// pure PKCS#12 primitives: a name as generic as `encodeHex` should not land in
/// the namespace of everyone importing the package. Import the path directly if
/// you want it.
String encodeHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
