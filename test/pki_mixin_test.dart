import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  group('PkiMixin', () {
    late OpenSSL openssl;

    setUpAll(() {
      openssl = OpenSSL();
    });

    test('generateSerialNumberBigInt rejects invalid byte sizes', () {
      expect(
        () => openssl.generateSerialNumberBigInt(bytes: 7),
        throwsRangeError,
      );
      expect(
        () => openssl.generateSerialNumberBigInt(bytes: 21),
        throwsRangeError,
      );
    });

    test('generateSerialNumberBigInt returns positive value', () {
      final serial = openssl.generateSerialNumberBigInt(bytes: 16);
      expect(serial, greaterThan(BigInt.zero));
    });

    test('generateSerialNumberBigInt stays within requested size', () {
      final serial = openssl.generateSerialNumberBigInt(bytes: 16);
      final hex = serial.toRadixString(16);
      final byteLen = (hex.length + 1) ~/ 2;
      expect(byteLen, inInclusiveRange(1, 16));
    });
  });
}
