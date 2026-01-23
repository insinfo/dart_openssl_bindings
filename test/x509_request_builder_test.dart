import 'package:test/test.dart';
import 'dart:ffi';
import 'package:openssl_bindings/src/api/openssl.dart';
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

    // 2. Build CSR
    final builder = X509RequestBuilder(openssl);
    builder.setSubject(
      commonName: 'Test User',
      country: 'US',
      organization: 'Test Corp'
    );
    builder.setPublicKey(pkey);
    final csr = builder.sign(pkey);
    
    expect(csr.handle, isNot(nullptr));

    // 4. Export to PEM
    final pem = csr.toPem();

    expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
    expect(pem, contains('-----END CERTIFICATE REQUEST-----'));
  });
}
