import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

import 'certs.dart';

void main() {
  group('ICP-Brasil extraction', () {
    late OpenSSL openssl;

    setUp(() {
      openssl = OpenSSL();
    });

    test('extracts fallback ICP-Brasil info from subject', () {
      final cert = openssl.loadCertificatePem(rawPemCertificate);
      final info = cert.icpBrasilInfo;

      expect(info.name, equals('ISRG Root X1'));
      expect(info.cpf, isNull);
      expect(info.birthDate, isNull);
    });
  });
}
