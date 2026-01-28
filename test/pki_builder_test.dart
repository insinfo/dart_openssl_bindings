import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  group('PkiBuilder', () {
    late OpenSSL openssl;

    setUpAll(() {
      openssl = OpenSSL();
    });

    test('creates user certificate with DN parsing and BigInt serial', () {
      final userKey = openssl.generateRsa(2048);
      final caKey = openssl.generateRsa(2048);
      final serial = openssl.generateSerialNumberBigInt(bytes: 16);

      final certDer = openssl.createUserCertificate(
        keyPair: userKey,
        issuerKeyPair: caKey,
        subjectDn: 'CN=User,OU=Prod,O=MyOrg,L=Sao Paulo,ST=SP,C=BR,E=user@example.com,SERIALNUMBER=123',
        issuerDn: 'CN=My CA,O=MyOrg,C=BR',
        serialNumberBigInt: serial,
        extendedKeyUsageOids: const ['1.3.6.1.5.5.7.3.2'],
      );

      final cert = openssl.loadCertificateDer(certDer);
      expect(cert.serialNumber, equals(serial.toString()));
      expect(cert.subject, contains('CN=User'));
      expect(cert.subject, contains('O=MyOrg'));
      expect(cert.subject, contains('emailAddress=user@example.com'));
      expect(cert.subject, contains('serialNumber=123'));
      expect(cert.issuer, contains('CN=My CA'));
      cert.dispose();
      userKey.dispose();
      caKey.dispose();
    });

    test('creates cross-cert rollover pair', () {
      final oldKey = openssl.generateRsa(2048);
      final newKey = openssl.generateRsa(2048);

      final oldBuilder = X509CertificateBuilder(openssl)
        ..setSubject(commonName: 'Old Root CA', organization: 'MyOrg')
        ..setIssuerAsSubject()
        ..setPublicKey(oldKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: true, critical: true)
        ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true);
      final oldCert = oldBuilder.sign(oldKey);

      final newBuilder = X509CertificateBuilder(openssl)
        ..setSubject(commonName: 'New Root CA', organization: 'MyOrg')
        ..setIssuerAsSubject()
        ..setPublicKey(newKey)
        ..setValidity(notAfterOffset: 3600)
        ..addBasicConstraints(isCa: true, critical: true)
        ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true);
      final newCert = newBuilder.sign(newKey);

      final rollover = openssl.createRolloverCrossCertificates(
        oldCaCert: oldCert,
        oldCaKey: oldKey,
        newCaCert: newCert,
        newCaKey: newKey,
        notAfterOffset: 3600,
      );

      final oldSignedByNew = openssl.loadCertificateDer(rollover.oldSignedByNew);
      final newSignedByOld = openssl.loadCertificateDer(rollover.newSignedByOld);

      expect(oldSignedByNew.subject, contains('CN=Old Root CA'));
      expect(oldSignedByNew.issuer, contains('CN=New Root CA'));
      expect(newSignedByOld.subject, contains('CN=New Root CA'));
      expect(newSignedByOld.issuer, contains('CN=Old Root CA'));

      oldSignedByNew.dispose();
      newSignedByOld.dispose();
      oldCert.dispose();
      newCert.dispose();
      oldKey.dispose();
      newKey.dispose();
    });
  });
}
