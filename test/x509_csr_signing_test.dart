import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_builder.dart';
import 'package:openssl_bindings/src/x509/x509_request_builder.dart';

void main() {
  late OpenSSL openssl;

  setUpAll(() {
    openssl = OpenSSL();
  });

  test('Should sign a CSR with a CA certificate', () {
    // 1. Setup CA
    final caKey = openssl.generateRsa(2048);
    final caBuilder = X509CertificateBuilder(openssl);
    caBuilder.setSubject(commonName: 'Test CA', organization: 'Test Corp');
    caBuilder.setIssuerAsSubject(); // Self-signed
    caBuilder.setPublicKey(caKey);
    final caCert = caBuilder.sign(caKey);

    // 2. Setup User & CSR
    final userKey = openssl.generateRsa(2048);
    
    final csrBuilder = X509RequestBuilder(openssl);
    csrBuilder.setSubject(
      commonName: 'User 1',
      country: 'US'
    );
    csrBuilder.setPublicKey(userKey);
    final csr = csrBuilder.sign(userKey);

    // 3. Sign CSR to create User Cert
    final certBuilder = X509CertificateBuilder(openssl);
    certBuilder.setSerialNumber(2); // Serial 2
    certBuilder.setSubjectFromCsr(csr);
    certBuilder.setPublicKeyFromCsr(csr);
    certBuilder.setIssuer(issuerCert: caCert);
    certBuilder.setValidity(notAfterOffset: 86400); // 1 day
    
    final userCert = certBuilder.sign(caKey); // Sign with CA Key
    
    // 4. Verify
    final pem = userCert.toPem();
    expect(pem, startsWith('-----BEGIN CERTIFICATE-----'));

    // Manual dispose to check for crash
    print('DEBUG: Disposing userCert');
    userCert.dispose();
    print('DEBUG: Disposing csr');
    csr.dispose();
    print('DEBUG: Disposing caCert');
    caCert.dispose();
    print('DEBUG: Disposing builders');
    caBuilder.dispose();
    csrBuilder.dispose();
    certBuilder.dispose();
    print('DEBUG: Disposed all manually');
  });
}
