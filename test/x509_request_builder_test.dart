import 'package:test/test.dart';
import 'dart:ffi';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_name.dart';
import 'package:openssl_bindings/src/x509/x509_request_builder.dart';

void main() {
  late OpenSSL openssl;

  setUpAll(() {
    openssl = OpenSSL();
  });

  test('Should create a valid CSR', () {
    // 1. Generate KeyPair
    final pkey = openssl.generateRsa(2048);
    expect(pkey.handle, isNot(nullptr));

    // 2. Create Subject
    final subject = X509Name(openssl.bindings.X509_NAME_new(), openssl, isOwned: true);
    subject.addEntry('CN', 'Test User');
    subject.addEntry('C', 'US');
    subject.addEntry('O', 'Test Corp');

    // 3. Build CSR
    final builder = X509RequestBuilder(openssl);
    final csr = builder.build(
      subject: subject,
      keyPair: pkey,
    );
    expect(csr.handle, isNot(nullptr));

    // 4. Export to PEM
    final pem = csr.toPem();
    print('Generated CSR:\n$pem');

    expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
    expect(pem, contains('-----END CERTIFICATE REQUEST-----'));
  });
}
