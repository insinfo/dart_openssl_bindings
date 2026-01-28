import 'dart:typed_data';

/// Base class for ASN.1 DER encoding.
abstract class Asn1Object {
  final int tag;
  Uint8List? _encodedCache;

  Asn1Object(this.tag);

  Uint8List get encodedBytes {
    if (_encodedCache != null) return _encodedCache!;
    final valueResponse = encodeValue();
    final lengthBytes = _encodeLength(valueResponse.length);
    final b = BytesBuilder(copy: false);
    b.addByte(tag);
    b.add(lengthBytes);
    b.add(valueResponse);
    _encodedCache = b.takeBytes();
    return _encodedCache!;
  }

  /// Subclasses must implement this to return the content bytes.
  Uint8List encodeValue();

  static Uint8List _encodeLength(int length) {
    if (length < 128) {
      return Uint8List.fromList([length]);
    }
    final bytes = <int>[];
    var l = length;
    while (l > 0) {
      bytes.add(l & 0xFF);
      l >>= 8;
    }
    bytes.add(0x80 | bytes.length); // 1st byte: 1xxxxxxx (num bytes)
    return Uint8List.fromList(bytes.reversed.toList());
  }
}

class Asn1Null extends Asn1Object {
  Asn1Null() : super(0x05); // NULL tag

  @override
  Uint8List encodeValue() => Uint8List(0);
}

class Asn1OctetString extends Asn1Object {
  final Uint8List octets;
  Asn1OctetString(this.octets) : super(0x04);

  @override
  Uint8List encodeValue() => octets;
}

class Asn1Integer extends Asn1Object {
  final BigInt value;
  Asn1Integer(this.value) : super(0x02);

  @override
  Uint8List encodeValue() {
    if (value == BigInt.zero) return Uint8List.fromList([0]);

    if (value > BigInt.zero) {
      final bytes = _unsignedToBytes(value);
      if ((bytes[0] & 0x80) != 0) {
        return Uint8List.fromList([0x00, ...bytes]);
      }
      return bytes;
    }

    final absValue = -value;
    var length = (absValue.bitLength + 7) ~/ 8;
    if (length == 0) length = 1;

    final maxPositive = BigInt.one << (length * 8 - 1);
    if (absValue > maxPositive) {
      length += 1;
    }

    final max = BigInt.one << (length * 8);
    final twosComplement = max - absValue;
    return _unsignedToBytes(twosComplement, length: length);
  }

  Uint8List _unsignedToBytes(BigInt value, {int? length}) {
    var hex = value.toRadixString(16);
    if (hex.length.isOdd) hex = '0$hex';

    final rawBytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      rawBytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }

    if (length != null && rawBytes.length < length) {
      final padding = List<int>.filled(length - rawBytes.length, 0x00);
      rawBytes.insertAll(0, padding);
    }

    return Uint8List.fromList(rawBytes);
  }
}

class Asn1ObjectIdentifier extends Asn1Object {
  final String oid;
  Asn1ObjectIdentifier(this.oid) : super(0x06);

  @override
  Uint8List encodeValue() {
    // 1.2.840...
    final parts = oid.split('.').map(int.parse).toList();
    if (parts.length < 2) throw ArgumentError('Invalid OID');
    
    final b = BytesBuilder();
    // First byte = parts[0] * 40 + parts[1]
    b.addByte(parts[0] * 40 + parts[1]);
    
    for (var i = 2; i < parts.length; i++) {
      _encodeBase128(b, parts[i]);
    }
    return b.takeBytes();
  }

  void _encodeBase128(BytesBuilder b, int val) {
     if (val == 0) {
       b.addByte(0);
       return;
     }
     final bytes = <int>[];
     var v = val;
     bytes.add(v & 0x7F);
     v >>= 7;
     while (v > 0) {
       bytes.add((v & 0x7F) | 0x80);
       v >>= 7;
     }
     for(var x in bytes.reversed) b.addByte(x);
  }
}

class Asn1Sequence extends Asn1Object {
  final List<Asn1Object> elements = [];
  Asn1Sequence([List<Asn1Object>? children]) : super(0x30) {
    if (children != null) elements.addAll(children);
  }

  void add(Asn1Object obj) => elements.add(obj);

  @override
  Uint8List encodeValue() {
    final b = BytesBuilder(copy: false);
    for (final e in elements) {
      b.add(e.encodedBytes);
    }
    return b.takeBytes();
  }
}

class Asn1Set extends Asn1Object {
  final List<Asn1Object> elements = [];
  Asn1Set([List<Asn1Object>? children]) : super(0x31) {
    if (children != null) elements.addAll(children);
  }

  void add(Asn1Object obj) => elements.add(obj);

  @override
  Uint8List encodeValue() {
    // DER requires Set elements to be sorted lexicographically
    elements.sort((a, b) {
      final ab = a.encodedBytes;
      final bb = b.encodedBytes;
      final len = ab.length < bb.length ? ab.length : bb.length;
      for (var i = 0; i < len; i++) {
        final d = ab[i] - bb[i];
        if (d != 0) return d;
      }
      return ab.length - bb.length;
    });

    final b = BytesBuilder(copy: false);
    for (final e in elements) {
      b.add(e.encodedBytes);
    }
    return b.takeBytes();
  }
}

// Wrapper for raw bytes to handle custom tagging without re-encoding value logic
class Asn1Raw extends Asn1Object {
  final Uint8List _value;
  Asn1Raw(int tag, this._value) : super(tag);
  
  @override
  Uint8List encodeValue() => _value;
  
  // Static helper to create from existing object with new tag
  // "Implicit" context tagging: keep content bytes, change tag.
  static Asn1Object fromImplicit(int tagNumber, Asn1Object inner) {
      // 0xA0 = Context(2) | Constructed(1) | TagNumber(5) ? 
      // Actually Context Specific is Class=10xxxxxx
      // Constructed is x01xxxxx.
      // So [0] IMPLICIT usually means TAG = 0x80 (Context primitive) or 0xA0 (Context constructed) + tagNum
      // For Constructed inner (like SET/SEQUENCE), we typically use Constructed [0] -> 0xA0.
      final newTag = 0xA0 | tagNumber;
      
      // But we need the value bytes of inner, NOT including inner's tag/length?
      // Wait. IMPLICIT means "replace types tag".
      // So we take inner.encodeValue() (the raw content)
      // And we wrap it with the new tag.
      return Asn1Raw(newTag, inner.encodeValue());
  }
  
  static Asn1Object fromExplicit(int tagNumber, Asn1Object inner) {
      final newTag = 0xA0 | tagNumber;
      return Asn1Raw(newTag, inner.encodedBytes);
  }
}

/// Minimal Parser Helper for extracting Cert details
class Asn1Reader {
  final Uint8List bytes;
  int offset = 0;

  Asn1Reader(this.bytes);

  // Returns (tag, fullBytes) of next object
  (int, Uint8List) readGeneric() {
     if (offset >= bytes.length) throw StateError('EOF');
     
     final start = offset;
     final tag = bytes[offset++];
     
     // Length
     int length = 0;
     int b = bytes[offset++];
     if ((b & 0x80) == 0) {
       length = b;
     } else {
       final octets = b & 0x7F;
       for (int i = 0; i < octets; i++) {
         length = (length << 8) + bytes[offset++];
       }
     }
     
     final end = offset + length;
     final fullBytes = bytes.sublist(start, end);
     
     // The value is from current offset to end
     // But we returned full bytes (including T L)
     
     // Move offset
     offset = end;
     return (tag, fullBytes);
  }

  // Reads T-L, returns V (value bytes)
  Uint8List readValue() {
     offset++; // skip tag
     int length = 0;
     int b = bytes[offset++];
     if ((b & 0x80) == 0) {
       length = b;
     } else {
       final count = b & 0x7F;
       for (int i = 0; i < count; i++) {
         length = (length << 8) + bytes[offset++];
       }
     }
     final value = bytes.sublist(offset, offset + length);
     offset += length;
     return value;
  }
}
