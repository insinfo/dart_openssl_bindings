import 'dart:typed_data';

/// Minimal DER reader, in pure Dart, good enough for PKCS#12 and PKCS#8.
///
/// It does not validate the whole encoding: it reads tag, length and content,
/// which is all that is needed to walk PKCS#12 structures. No FFI involved.
class DerValue {
  /// Full identifier byte (class + constructed bit + tag number).
  final int tag;

  /// Content bytes, without the tag and the length.
  final Uint8List content;

  const DerValue(this.tag, this.content);

  /// Whether the 0x20 bit of the identifier is set.
  bool get constructed => (tag & 0x20) != 0;

  /// Tag number, without the class bits and the constructed bit.
  int get tagNumber => tag & 0x1f;

  /// Whether this is a context-specific tag (`[0]`, `[1]`, ...).
  bool get contextSpecific => (tag & 0xc0) == 0x80;

  /// Child values, for constructed types (SEQUENCE, SET, `[n]`).
  List<DerValue> get elements => DerReader(content).readAll();

  /// First child, or `null` when there is none.
  DerValue? get first {
    final children = elements;
    return children.isEmpty ? null : children.first;
  }

  /// Reads the content as an OBJECT IDENTIFIER (`1.2.840...`).
  String get oid {
    if (content.isEmpty) return '';
    final parts = <String>[];
    final firstByte = content[0];
    parts.add('${firstByte ~/ 40}');
    parts.add('${firstByte % 40}');

    var value = 0;
    var pending = false;
    for (var i = 1; i < content.length; i++) {
      final b = content[i];
      value = (value << 7) | (b & 0x7f);
      pending = true;
      if (b & 0x80 == 0) {
        parts.add('$value');
        value = 0;
        pending = false;
      }
    }
    if (pending) {
      throw const FormatException('Truncated DER OID');
    }
    return parts.join('.');
  }

  /// Reads the content as an unsigned INTEGER.
  int get asInt {
    var value = 0;
    for (final b in content) {
      value = (value << 8) | b;
    }
    return value;
  }

  /// Content of an OCTET STRING. For constructed context tags
  /// (`[0] EXPLICIT`), returns the content of the inner OCTET STRING.
  Uint8List get octets {
    if (tag == 0x04) return content;
    if (constructed) {
      final child = first;
      if (child != null && child.tag == 0x04) return child.content;
      // [0] EXPLICIT wrapping anything else: return it as is.
      return content;
    }
    return content;
  }

  /// Re-encodes this value (tag + length + content) back to DER.
  Uint8List get bytes {
    final length = _encodeLength(content.length);
    final out = Uint8List(1 + length.length + content.length);
    out[0] = tag;
    out.setRange(1, 1 + length.length, length);
    out.setRange(1 + length.length, out.length, content);
    return out;
  }

  @override
  String toString() =>
      'DerValue(tag: 0x${tag.toRadixString(16)}, ${content.length} bytes)';
}

/// Sequential reader of DER values.
class DerReader {
  final Uint8List _bytes;
  int _pos;

  DerReader(this._bytes, [this._pos = 0]);

  /// Whether there are bytes left to read.
  bool get hasMore => _pos < _bytes.length;

  /// Reads the next value.
  DerValue read() {
    if (_pos >= _bytes.length) {
      throw const FormatException('Truncated DER: expected a tag');
    }

    var tag = _bytes[_pos++];
    if (tag & 0x1f == 0x1f) {
      // Multi-byte tag: skip until the byte without the continuation bit.
      while (_pos < _bytes.length && _bytes[_pos] & 0x80 != 0) {
        _pos++;
      }
      if (_pos >= _bytes.length) {
        throw const FormatException('Truncated DER: long-form tag');
      }
      _pos++;
    }

    if (_pos >= _bytes.length) {
      throw const FormatException('Truncated DER: expected a length');
    }

    var length = _bytes[_pos++];
    if (length & 0x80 != 0) {
      final lengthBytes = length & 0x7f;
      if (lengthBytes == 0) {
        throw const FormatException('Indefinite DER length is not supported');
      }
      if (lengthBytes > 4 || _pos + lengthBytes > _bytes.length) {
        throw const FormatException('Invalid DER length');
      }
      length = 0;
      for (var i = 0; i < lengthBytes; i++) {
        length = (length << 8) | _bytes[_pos++];
      }
    }

    if (_pos + length > _bytes.length) {
      throw FormatException('Truncated DER: length $length exceeds the buffer');
    }

    final content = Uint8List.sublistView(_bytes, _pos, _pos + length);
    _pos += length;
    return DerValue(tag, content);
  }

  /// Reads every remaining value.
  List<DerValue> readAll() {
    final values = <DerValue>[];
    while (hasMore) {
      values.add(read());
    }
    return values;
  }
}

/// Reads the first DER value of [bytes].
DerValue readDer(Uint8List bytes) => DerReader(bytes).read();

Uint8List _encodeLength(int length) {
  if (length < 0x80) return Uint8List.fromList([length]);

  final octets = <int>[];
  var remaining = length;
  while (remaining > 0) {
    octets.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return Uint8List.fromList([0x80 | octets.length, ...octets]);
}
