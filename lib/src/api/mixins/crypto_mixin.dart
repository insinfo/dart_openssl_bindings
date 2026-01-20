import 'dart:ffi';
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

  /// Carrega uma Chave Privada de PEM.
  EvpPkey loadPrivateKeyPem(String pem) {
    final bio = createBioFromString(pem);
    try {
       // Precisamos usar o lookup do loader, ou bindings se tivermos mapeado.
       // Como PEM_read... foi adicionado ao ffi.dart, usamos bindings diretamente.
       
       final pkey = bindings.PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
       if (pkey == nullptr) throw OpenSslException('Failed to read private key');
       
       return EvpPkey(pkey, this as dynamic);
    } finally {
      freeBio(bio);
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
}
