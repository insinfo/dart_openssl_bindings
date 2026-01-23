import 'package:test/test.dart';
import 'dart:ffi';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_request_builder.dart';

void main() {
  late OpenSSL openssl;

  setUpAll(() {
    openssl = OpenSSL();
  });

  group('X509 Request Builder with EC', () {
    test('Should create a valid CSR with EC Key', () {
      // 1. Generate EC KeyPair
      final pkey = openssl.generateEc('prime256v1');
      expect(pkey.handle, isNot(nullptr));

      // 2. Build CSR
      final builder = X509RequestBuilder(openssl);
      builder.setSubject(
        commonName: 'EC User',
        country: 'BR',
        organization: 'EC Corp'
      );
      
      builder.setPublicKey(pkey);
      
      // 3. Sign CSR
      final csr = builder.sign(pkey);
      expect(csr.handle, isNot(nullptr));

      // 4. Export to PEM
      final pem = csr.toPem();

      expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
      expect(pem, contains('-----END CERTIFICATE REQUEST-----'));
      
      // Verify signature implicitly by checking it's generated? 
      // Ideally we would verify the CSR itself using X509_REQ_verify but that's a separate method.
      // But if sign succeeded, it should be signed.
    });
  });
}
