import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

import 'certs.dart';

void main() {
  group('PEM chain helpers', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('splits and loads PEM chain', () {
      final chain = '$rawPemCertificate\n$rawPemCertificate';
      final blocks = openSsl.splitPemChain(chain);
      expect(blocks.length, equals(2));

      final certs = openSsl.loadCertificatesFromPemChain(chain);
      expect(certs.length, equals(2));
      expect(certs.first.subject, isNotEmpty);
    });

    test('converts PEM chain to DER list', () {
      final chain = '$rawPemCertificate\n$rawPemCertificate';
      final ders = openSsl.convertPemChainToDerList(chain);
      expect(ders.length, equals(2));
      expect(ders.first, isNotEmpty);
    });
  });
}
