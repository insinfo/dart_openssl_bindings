import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

import 'certs.dart';

void main() {
  group('ASN1 serial APIs', () {
    late OpenSSL openssl;

    setUp(() {
      openssl = OpenSSL();
    });

    test('reads serial bytes without truncating leading 0x00', () {
      final cert =
          openssl.loadCertificateDer(Uint8List.fromList(rawDerCertificate));

      final serialBytes = openssl.x509GetSerialBytes(cert.handle);
      final serialHex = openssl.x509GetSerialHex(cert.handle, prefixed: false);
      final serialDec = openssl.x509GetSerialDecimal(cert.handle);

      expect(serialBytes, isNotEmpty);
      expect(serialHex, equals(_toHex(serialBytes)));
      expect(serialDec, equals(cert.serialNumber));
    });

    test('converts ASN1 integer from hex to decimal safely', () {
      final asn1 = openssl.asn1IntegerFromHex('0x00:AA:10');
      try {
        final decimal = openssl.asn1IntegerToDecimal(asn1);
        final hex = openssl.asn1IntegerToHex(asn1);

        expect(decimal, equals(BigInt.parse('AA10', radix: 16).toString()));
        expect(hex.toLowerCase(), equals('aa10'));
      } finally {
        openssl.bindings.ASN1_INTEGER_free(asn1);
      }
    });

    test('returns prefixed serial hex when requested', () {
      final cert =
          openssl.loadCertificateDer(Uint8List.fromList(rawDerCertificate));

      final serialHexPrefixed = openssl.x509GetSerialHex(cert.handle);
      final serialHexRaw =
          openssl.x509GetSerialHex(cert.handle, prefixed: false);

      expect(serialHexPrefixed, equals('0x$serialHexRaw'));
    });

    test('normalizes odd-length and mixed-format hex input', () {
      final asn1 = openssl.asn1IntegerFromHex(' 0Xabc ');
      try {
        expect(openssl.asn1IntegerToHex(asn1).toLowerCase(), equals('0abc'));
        expect(
          openssl.asn1IntegerToDecimal(asn1),
          equals(BigInt.parse('0abc', radix: 16).toString()),
        );
      } finally {
        openssl.bindings.ASN1_INTEGER_free(asn1);
      }
    });

    test('accepts hex with separators and spaces', () {
      final asn1 = openssl.asn1IntegerFromHex('AA: BB 0C');
      try {
        expect(openssl.asn1IntegerToHex(asn1).toLowerCase(), equals('aabb0c'));
      } finally {
        openssl.bindings.ASN1_INTEGER_free(asn1);
      }
    });

    test('throws ArgumentError for invalid hex characters', () {
      expect(
        () => openssl.asn1IntegerFromHex('0x12G7'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError for empty hex payload', () {
      expect(
        () => openssl.asn1IntegerFromHex(' 0x  '),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('encodes ASN1 integer to DER with INTEGER tag', () {
      final asn1 = openssl.asn1IntegerFromHex('0x2a');
      try {
        final der = openssl.encodeAsn1Integer(asn1);
        expect(der, isNotEmpty);
        expect(der.first, equals(0x02));
      } finally {
        openssl.bindings.ASN1_INTEGER_free(asn1);
      }
    });

    test('extracts issuer and serial DER from certificate DER', () {
      final der = Uint8List.fromList(rawDerCertificate);
      final extracted = openssl.extractIssuerAndSerialDer(der);

      expect(extracted.issuerDer, isNotEmpty);
      expect(extracted.serialDer, isNotEmpty);
      expect(extracted.issuerDer.first, equals(0x30));
      expect(extracted.serialDer.first, equals(0x02));
    });

    test('throws on invalid DER when loading certificate', () {
      expect(
        () => openssl.loadCertificateDer(Uint8List.fromList(const [1, 2, 3])),
        throwsA(isA<OpenSslException>()),
      );
    });

    test('throws on invalid DER when extracting issuer and serial', () {
      expect(
        () => openssl.extractIssuerAndSerialDer(
          Uint8List.fromList(const [0x30, 0x01]),
        ),
        throwsA(isA<OpenSslException>()),
      );
    });
  });
}

String _toHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
