import 'package:test/test.dart';
import 'package:openssl_bindings/src/cms/asn1_utils.dart';

void main() {
  group('Asn1Integer', () {
    test('encodes positive values with sign padding', () {
      expect(Asn1Integer(BigInt.from(127)).encodeValue(), equals([0x7F]));
      expect(Asn1Integer(BigInt.from(128)).encodeValue(), equals([0x00, 0x80]));
    });

    test('encodes negative values in two\'s complement', () {
      expect(Asn1Integer(BigInt.from(-1)).encodeValue(), equals([0xFF]));
      expect(Asn1Integer(BigInt.from(-128)).encodeValue(), equals([0x80]));
      expect(Asn1Integer(BigInt.from(-129)).encodeValue(), equals([0xFF, 0x7F]));
      expect(Asn1Integer(BigInt.from(-256)).encodeValue(), equals([0xFF, 0x00]));
    });
  });
}
