import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';
import 'package:openssl_bindings/src/x509/x509_name.dart';
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
    print('CA Certificate created');

    // 2. Setup User & CSR
    final userKey = openssl.generateRsa(2048);
    final userSubject = X509Name(openssl.bindings.X509_NAME_new(), openssl, isOwned: true);
    userSubject.addEntry('CN', 'User 1');
    userSubject.addEntry('C', 'US');
    
    final csrBuilder = X509RequestBuilder(openssl);
    final csr = csrBuilder.build(subject: userSubject, keyPair: userKey);
    print('CSR created');

    // 3. Sign CSR to create User Cert
    final certBuilder = X509CertificateBuilder(openssl);
    certBuilder.setSerialNumber(2); // Serial 2
    certBuilder.setSubjectFromCsr(csr);
    certBuilder.setPublicKeyFromCsr(csr);
    certBuilder.setIssuer(issuerCert: caCert);
    certBuilder.setValidity(notAfterOffset: 86400); // 1 day
    
    final userCert = certBuilder.sign(caKey); // Sign with CA Key
    print('User Certificate created');
    
    // 4. Verify
    final pem = userCert.toPem();
    print('User Certificate PEM:\n$pem');
    expect(pem, startsWith('-----BEGIN CERTIFICATE-----'));
    
    // Check Issuer
    // Note: We don't have easy getters for content yet exposed in X509Certificate wrapper,
    // but the fact it generated and signed without error is the main test here.
    
    // We can check if verification works (if we exposed X509_verify)
    // For now we rely on the builder sequence success.
  });
}
