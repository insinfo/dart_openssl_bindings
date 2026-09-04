import 'dart:typed_data';

/// Encodes [bytes] as lowercase hexadecimal, two digits per byte.
///
/// This is the representation `package:crypto`'s `Digest.toString()` produces
/// and the one most systems store digests in. `OpenSSL.digestHex`,
/// `OpenSSL.hmacHex` and `EvpDigest.finishHex` are this applied to their byte
/// results; use it directly for anything else — a serial number, a key id, a
/// fingerprint.
String encodeHex(List<int> bytes) {
  const digits = '0123456789abcdef';
  final out = StringBuffer();
  for (final byte in bytes) {
    out.writeCharCode(digits.codeUnitAt((byte >> 4) & 0xf));
    out.writeCharCode(digits.codeUnitAt(byte & 0xf));
  }
  return out.toString();
}

/// Decodes hexadecimal [text] into bytes. Accepts either case.
///
/// Throws [FormatException] on an odd length or a character outside `0-9`,
/// `a-f`, `A-F` — there is no lenient mode, because a stored hash that does
/// not parse is a problem to surface, not to paper over.
Uint8List decodeHex(String text) {
  if (text.length.isOdd) {
    throw FormatException('Hex string has an odd length', text);
  }
  final out = Uint8List(text.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final high = _hexDigit(text, i * 2);
    final low = _hexDigit(text, i * 2 + 1);
    out[i] = (high << 4) | low;
  }
  return out;
}

int _hexDigit(String text, int index) {
  final code = text.codeUnitAt(index);
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10; // A-F
  throw FormatException('Not a hex digit', text, index);
}
