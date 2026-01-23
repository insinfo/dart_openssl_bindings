import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:openssl_bindings/src/api/openssl.dart';

void main() {
  group('CipherMixin (AES-GCM)', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Deve encriptar e decriptar com AES-256-GCM', () {
      final key = Uint8List(32); // Chave zero (só para teste)
      final iv = Uint8List(12);  // IV zero
      final data = utf8.encode('Mensagem Secreta Super Importante');
      final aad = utf8.encode('Dados Abertos');

      // 1. Encrypt
      final result = openSsl.aes256GcmEncrypt(
        data: Uint8List.fromList(data),
        key: key,
        iv: iv,
        aad: Uint8List.fromList(aad),
      );

      expect(result['ciphertext'], isNotNull);
      expect(result['tag'], isNotNull);
      expect(result['tag']!.length, equals(16));
      expect(result['ciphertext']!.length, equals(data.length));

      // 2. Decrypt (Sucesso)
      final decrypted = openSsl.aes256GcmDecrypt(
        ciphertext: result['ciphertext']!,
        key: key,
        iv: iv,
        tag: result['tag']!,
        aad: Uint8List.fromList(aad)
      );

      expect(utf8.decode(decrypted), equals('Mensagem Secreta Super Importante'));
    });

    test('Deve falhar decriptação se Tag estiver errada', () {
      final key = Uint8List(32);
      final iv = Uint8List(12);
      final data = utf8.encode('Teste');
      
      final result = openSsl.aes256GcmEncrypt(
        data: Uint8List.fromList(data),
        key: key,
        iv: iv
      );

      final badTag = result['tag']!;
      badTag[0] = badTag[0] ^ 0xFF; // Corrompe tag

      expect(
        () => openSsl.aes256GcmDecrypt(
          ciphertext: result['ciphertext']!,
          key: key,
          iv: iv,
          tag: badTag
        ),
        throwsException // OpenSslException
      );
    });

    test('Deve falhar decriptação se AAD estiver errado', () {
      final key = Uint8List(32);
      final iv = Uint8List(12);
      final data = Uint8List.fromList([1, 2, 3]);
      final aad = Uint8List.fromList([10, 20]);

      final result = openSsl.aes256GcmEncrypt(data: data, key: key, iv: iv, aad: aad);

      final badAad = Uint8List.fromList([10, 21]); // AAD diferente

      expect(
        () => openSsl.aes256GcmDecrypt(
          ciphertext: result['ciphertext']!,
          key: key,
          iv: iv,
          tag: result['tag']!,
          aad: badAad
        ),
        throwsException
      );
    });
  });

  group('CipherMixin (AES-CBC)', () {
    late OpenSSL openSsl;

    setUp(() {
      openSsl = OpenSSL();
    });

    test('Deve encriptar e decriptar com AES-256-CBC (PKCS7)', () {
      final key = Uint8List(32); // Chave zero (teste)
      final iv = Uint8List(16);  // IV zero
      final data = utf8.encode('Mensagem com tamanho irregular');

      final ciphertext = openSsl.aes256CbcEncrypt(
        data: Uint8List.fromList(data),
        key: key,
        iv: iv,
      );

      expect(ciphertext, isNotEmpty);

      final decrypted = openSsl.aes256CbcDecrypt(
        ciphertext: ciphertext,
        key: key,
        iv: iv,
      );

      expect(utf8.decode(decrypted), equals('Mensagem com tamanho irregular'));
    });

    test('Deve falhar decriptação se padding for inválido', () {
      final key = Uint8List(32);
      final iv = Uint8List(16);
      final data = utf8.encode('Teste CBC');

      final ciphertext = openSsl.aes256CbcEncrypt(
        data: Uint8List.fromList(data),
        key: key,
        iv: iv,
      );

      final tampered = Uint8List.fromList(ciphertext);
      tampered[tampered.length - 1] = 0x00; // Padding inválido (PKCS7 exige 1..16)

      expect(
        () => openSsl.aes256CbcDecrypt(
          ciphertext: tampered,
          key: key,
          iv: iv,
        ),
        throwsException,
      );
    });

    test('Deve falhar com chave/IV inválidos', () {
      final data = Uint8List.fromList([1, 2, 3]);
      expect(
        () => openSsl.aes256CbcEncrypt(
          data: data,
          key: Uint8List(16),
          iv: Uint8List(16),
        ),
        throwsArgumentError,
      );

      expect(
        () => openSsl.aes256CbcEncrypt(
          data: data,
          key: Uint8List(32),
          iv: Uint8List(12),
        ),
        throwsArgumentError,
      );
    });
  });
}
