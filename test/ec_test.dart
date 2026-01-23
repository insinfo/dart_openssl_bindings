import 'package:openssl_bindings/openssl.dart';
import 'package:test/test.dart';

void main() {
  group('Elliptic Curve Key Generation', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Should generate EC key (prime256v1)', () {
      try {
        final key = openSsl.generateEc('prime256v1');
        expect(key, isNotNull);
        
        final pem = key.toPrivateKeyPem();
        
        expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));
        // EC keys in PKCS8 usually look like generic private keys, 
        // but if we exported as traditional OpenSSL EC format it would be BEGIN EC PRIVATE KEY.
        // EvpPkey.toPrivateKeyPem uses PEM_write_bio_PrivateKey which uses PKCS8 by default in newer OpenSSL versions sometimes,
        // or traditionally. Let's check output.
        // It definitely shouldn't be empty.
      } catch (e) {
        // If the dynamic lookup fails (e.g. symbols missing in DLL), we want to know.
        fail('EC Generation failed: $e');
      }
    });

    test('Should fail for invalid curve', () {
       expect(() => openSsl.generateEc('invalid_curve_name'), throwsA(isA<OpenSslException>()));
    });

    test('Should compute shared secret (ECDH)', () {
       final aliceKey = openSsl.generateEc('prime256v1');
       final bobKey = openSsl.generateEc('prime256v1');
       
       final secretAlice = openSsl.computeSharedSecret(aliceKey, bobKey);
       final secretBob = openSsl.computeSharedSecret(bobKey, aliceKey);
       
       expect(secretAlice, equals(secretBob));
       // For P-256 (prime256v1), shared secret is 32 bytes
       expect(secretAlice.length, equals(32));
    });
  });
}
