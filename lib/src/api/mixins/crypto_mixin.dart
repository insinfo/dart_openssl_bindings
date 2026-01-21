import 'dart:ffi'; 
import 'dart:typed_data'; // Add typed_data
import 'package:ffi/ffi.dart'; // Add ffi/ffi

import '../openssl_context.dart';
import '../../infra/ssl_exception.dart';
import '../../crypto/evp_pkey.dart'; // Vamos atualizar este arquivo em breve
import 'bio_mixin.dart';

/// Mixin para operações criptográficas e gerenciamento de chaves.
mixin CryptoMixin on OpenSslContext, BioMixin {
  
  /// Gera um par de chaves RSA.
  EvpPkey generateRsa(int bits) {
    final rsa = bindings.RSA_new();
    if (rsa == nullptr) throw OpenSslException('Failed to create RSA object');

    final bne = bindings.BN_new();
    if (bne == nullptr) {
      bindings.RSA_free(rsa);
      throw OpenSslException('Failed to create BIGNUM');
    }

    try {
      if (bindings.BN_set_word(bne, 65537) != 1) { // 0x10001
         throw OpenSslException('BN_set_word failed');
      }

      if (bindings.RSA_generate_key_ex(rsa, bits, bne, nullptr) != 1) {
        throw OpenSslException('RSA_generate_key_ex failed');
      }

      final pkey = bindings.EVP_PKEY_new();
      if (pkey == nullptr) throw OpenSslException('EVP_PKEY_new failed');

      if (bindings.EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        bindings.EVP_PKEY_free(pkey);
        throw OpenSslException('EVP_PKEY_set1_RSA failed');
      }
      
      // Retorna o wrapper injetando 'this' como contexto
      // cast implicito 'this' satisfaz OpenSSL (a classe principal)
      return EvpPkey(pkey, this as dynamic); 
    } finally {
      bindings.RSA_free(rsa);
      bindings.BN_free(bne);
    }
  }

  /// Carrega uma Chave Privada de PEM, opcionalmente decifrando com [password].
  EvpPkey loadPrivateKeyPem(String pem, {String? password}) {
    final bio = createBioFromString(pem);
    Pointer<Char> passwordPtr = nullptr;
    if (password != null) {
      passwordPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
    }

    try {
      // Se password for fornecido, passamos como 4o argumento (u).
      // Se cb (3o arg) for NULL e u não for NULL, OpenSSL usa u como senha.
      final pkey = bindings.PEM_read_bio_PrivateKey(
        bio,
        nullptr,
        nullptr,
        passwordPtr.cast(),
      );

      if (pkey == nullptr) {
         // Tenta pegar o erro do OpenSSL para detalhar
         throw OpenSslException('Failed to read private key (check password?)');
      }

      return EvpPkey(pkey, this as dynamic);
    } finally {
      freeBio(bio);
      if (passwordPtr != nullptr) {
        calloc.free(passwordPtr);
      }
    }
  }

  /// Carrega um Chave Pública de PEM.
  EvpPkey loadPublicKeyPem(String pem) {
    final bio = createBioFromString(pem);
    try {
      final pkey = bindings.PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
      if (pkey == nullptr) throw OpenSslException('Failed to read public key');
      return EvpPkey(pkey, this as dynamic);
    } finally {
      freeBio(bio);
    }
  }

  /// Computes SHA-256 digest of [data].
  Uint8List sha256(List<int> data) {
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_MD_CTX');

    try {
      final sha256 = bindings.EVP_sha256();
      if (bindings.EVP_DigestInit_ex(ctx, sha256, nullptr) != 1) {
        throw OpenSslException('EVP_DigestInit_ex failed');
      }
      
      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      
      try {
        if (bindings.EVP_DigestUpdate(ctx, dataPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_DigestUpdate failed');
        }
      } finally {
        calloc.free(dataPtr);
      }

      final hashPart = calloc<Uint8>(32); // SHA256 is 32 bytes
      final lenPtr = calloc<UnsignedInt>();
      
      try {
        if (bindings.EVP_DigestFinal_ex(ctx, hashPart.cast(), lenPtr) != 1) {
          throw OpenSslException('EVP_DigestFinal_ex failed');
        }
        return Uint8List.fromList(hashPart.asTypedList(lenPtr.value));
      } finally {
        calloc.free(hashPart);
        calloc.free(lenPtr);
      }

    } finally {
        bindings.EVP_MD_CTX_free(ctx);
    }
  }
}
