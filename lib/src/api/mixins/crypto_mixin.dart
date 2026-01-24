import 'dart:convert';
import 'dart:ffi'; 
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../../generated/ffi.dart';
import '../openssl_context.dart';
import '../../infra/ssl_exception.dart';
import '../../crypto/evp_pkey.dart';
import 'bio_mixin.dart';

Pointer<Uint8> _allocUtf8z(String s) {
  final bytes = utf8.encode(s);
  final p = calloc<Uint8>(bytes.length + 1);
  p.asTypedList(bytes.length).setAll(0, bytes);
  p[bytes.length] = 0; // NUL
  return p;
}

String _drainOpenSslErrors(OpenSslFfi lib) {
  final msgs = <String>[];
  while (true) {
    final err = lib.ERR_get_error();
    if (err == 0) break;
    final p = lib.ERR_error_string(err, nullptr);
    msgs.add(p == nullptr ? 'OpenSSL error $err' : p.cast<Utf8>().toDartString());
  }
  return msgs.isEmpty ? '' : msgs.join('\n');
}

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
    Pointer<Uint8>? pw;

    try {
      if (password != null) {
        pw = _allocUtf8z(password);
      }
      
      // When callback is null but userdata is provided, OpenSSL uses it as password directly
      final pkey = bindings.PEM_read_bio_PrivateKey(
        bio,
        nullptr,
        nullptr, // No callback - OpenSSL will use default behavior
        pw?.cast<Void>() ?? nullptr,
      );

      if (pkey == nullptr) {
         final details = _drainOpenSslErrors(bindings);
         throw OpenSslException(
           'Failed to read private key.\n${details.isEmpty ? '(no OpenSSL error details)' : details}',
         );
      }

      return EvpPkey(pkey, this as dynamic);
    } finally {
      freeBio(bio);
      if (pw != null) calloc.free(pw);
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

  /// Deriva uma chave a partir de uma senha usando PBKDF2-HMAC-SHA256.
  /// 
  /// [password]: A senha.
  /// [salt]: O salt aleatório.
  /// [iterations]: Número de iterações (default: 10000).
  /// [keyLength]: Tamanho da chave desejada em bytes (default: 32 bytes / 256 bits).
  Uint8List pbkdf2({
    required Uint8List password,
    required Uint8List salt,
    int iterations = 10000,
    int keyLength = 32,
  }) {
    final ctx = bindings.HMAC_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create HMAC_CTX');

    final messageDigest = bindings.EVP_sha256();
    // SHA256 block size is 32 bytes
    const hLen = 32; 
    
    // ceil(keyLength / hLen)
    final blockCount = (keyLength / hLen).ceil();
    // Buffer for the final result (might be slightly larger than keyLength initially)
    final fullResult = Uint8List(blockCount * hLen);

    final arena = Arena();
    try {
      final passPtr = arena<UnsignedChar>(password.length);
      passPtr.cast<Uint8>().asTypedList(password.length).setAll(0, password);

      // Salt buffer needs space for 4-byte counter appended
      final saltPlusCountPtr = arena<UnsignedChar>(salt.length + 4);
      saltPlusCountPtr.cast<Uint8>().asTypedList(salt.length).setAll(0, salt);

      // Helper for pointers
      final uBlockPtr = arena<UnsignedChar>(hLen); // U_j
      final outLenPtr = arena<UnsignedInt>(1);
      final tBlock = Uint8List(hLen);              // T_i accumulator

      // 1. Initialize HMAC with Password as Key.
      // This key will be reused for all iterations.
      if (bindings.HMAC_Init_ex(ctx, passPtr.cast(), password.length, messageDigest, nullptr) != 1) {
        throw OpenSslException('HMAC_Init_ex failed to set key');
      }

      int resultOffset = 0;

      for (int i = 1; i <= blockCount; i++) {
        // --- Block i ---
        // T_i = F(P, S, c, i) = U_1 ^ U_2 ^ ... ^ U_c

        // 1. Calculate U_1 = PRF(P, S || INT_32_BE(i))
        
        // Update the counter part of saltPlusCountPtr
        // INT_32_BE(i)
        final iBytes = ByteData(4)..setUint32(0, i, Endian.big);
        final iList = iBytes.buffer.asUint8List();
        final saltSuffixPtr = saltPlusCountPtr + salt.length;
        for (int b = 0; b < 4; b++) {
          (saltSuffixPtr + b).value = iList[b];
        }

        // Run HMAC for U_1
        // Reuse key (pass nullptr)
        if (bindings.HMAC_Init_ex(ctx, nullptr, 0, nullptr, nullptr) != 1) {
           throw OpenSslException('HMAC_Init_ex failed at block $i');
        }
        if (bindings.HMAC_Update(ctx, saltPlusCountPtr, salt.length + 4) != 1) {
           throw OpenSslException('HMAC_Update failed at block $i');
        }
        if (bindings.HMAC_Final(ctx, uBlockPtr, outLenPtr) != 1) {
           throw OpenSslException('HMAC_Final failed at block $i');
        }

        // Copy U_1 to T_i accumulator
        final uList = uBlockPtr.cast<Uint8>().asTypedList(hLen);
        tBlock.setAll(0, uList); // T_i = U_1

        // 2. Loop U_2 ... U_iterations
        for (int j = 2; j <= iterations; j++) {
           // U_j = PRF(P, U_{j-1})
           // Reuse key
           if (bindings.HMAC_Init_ex(ctx, nullptr, 0, nullptr, nullptr) != 1) {
             throw OpenSslException('HMAC_Init_ex failed at iter $j');
           }
           if (bindings.HMAC_Update(ctx, uBlockPtr, hLen) != 1) {
             throw OpenSslException('HMAC_Update failed at iter $j');
           }
           if (bindings.HMAC_Final(ctx, uBlockPtr, outLenPtr) != 1) {
             throw OpenSslException('HMAC_Final failed at iter $j');
           }

           // XOR into T_i
           // uList is now U_j because HMAC_Final writes to uBlockPtr
           for (int k = 0; k < hLen; k++) {
             tBlock[k] ^= uList[k];
           }
        }

        // Block i complete. Append T_i to result.
        fullResult.setRange(resultOffset, resultOffset + hLen, tBlock);
        resultOffset += hLen;
      }

      // 3. Truncate to keyLength
      if (keyLength < fullResult.length) {
        return fullResult.sublist(0, keyLength);
      }
      return fullResult;

    } finally {
      bindings.HMAC_CTX_free(ctx);
      arena.releaseAll();
    }
  }

  /// Gera um par de chaves EC (Elliptic Curve).
  /// 
  /// [curveName]: Nome da curva (ex: 'prime256v1', 'secp384r1').
  EvpPkey generateEc(String curveName) {
     final arena = Arena();
     try {
       // 1. Create Context for "EC"
       final namePtr = "EC".toNativeUtf8(allocator: arena);
       final ctx = bindings.EVP_PKEY_CTX_new_from_name(nullptr, namePtr.cast(), nullptr);
       if (ctx == nullptr) throw OpenSslException('EVP_PKEY_CTX_new_from_name failed');
       
       try {
         // 2. Init Keygen
         if (bindings.EVP_PKEY_keygen_init(ctx) <= 0) {
            throw OpenSslException('EVP_PKEY_keygen_init failed');
         }
         
         // 3. Set Params (group = curveName)
         final groupKey = "group".toNativeUtf8(allocator: arena);
         final curveNameUtf8 = curveName.toNativeUtf8(allocator: arena);
         
         // Construct OSSL_PARAM array (size 2: 1 param + 1 terminator)
         final params = arena<OSSL_PARAM>(2);
         
         // Param 0: group
         final p0 = params[0];
         p0.key = groupKey.cast();
         p0.data_type = 4; // OSSL_PARAM_UTF8_STRING
         p0.data = curveNameUtf8.cast();
         p0.data_size = 0;
         p0.return_size = 0;
         
         // Param 1: Terminator (all null)
         final p1 = params[1];
         p1.key = nullptr;
         p1.data_type = 0;
         p1.data = nullptr;
         p1.data_size = 0;
         p1.return_size = 0;
         
         if (bindings.EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
            throw OpenSslException('EVP_PKEY_CTX_set_params failed for curve $curveName');
         }
         
         // 4. Generate
         final pkeyPtr = arena<Pointer<EVP_PKEY>>();
         if (bindings.EVP_PKEY_keygen(ctx, pkeyPtr) <= 0) {
            throw OpenSslException('EVP_PKEY_keygen failed');
         }
         
         return EvpPkey(pkeyPtr.value, this as dynamic);
       } finally {
         bindings.EVP_PKEY_CTX_free(ctx);
       }
     } finally {
       arena.releaseAll();
     }
  }

  /// Calcula o hash (digest) dos dados usando o algoritmo especificado.
  /// 
  /// [algorithmName]: Nome do algoritmo (ex: 'sha256', 'sha512', 'sha3-256').
  /// [data]: Dados para hashear.
  Uint8List digest(String algorithmName, Uint8List data) {
    final arena = Arena();
    try {
      final namePtr = algorithmName.toNativeUtf8(allocator: arena);
      final md = bindings.EVP_get_digestbyname(namePtr.cast());
      if (md == nullptr) throw OpenSslException('Unknown digest algorithm: $algorithmName');
      
      final ctx = bindings.EVP_MD_CTX_new();
      if (ctx == nullptr) throw OpenSslException('Failed to create EVP_MD_CTX');

      try {
        if (bindings.EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
          throw OpenSslException('EVP_DigestInit_ex failed');
        }
        
        final dataPtr = arena<UnsignedChar>(data.length);
        dataPtr.cast<Uint8>().asTypedList(data.length).setAll(0, data);
        
        if (bindings.EVP_DigestUpdate(ctx, dataPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_DigestUpdate failed');
        }
        
        final outPtr = arena<UnsignedChar>(128); // Safe size
        final outLenPtr = arena<UnsignedInt>(1);
        
        if (bindings.EVP_DigestFinal_ex(ctx, outPtr, outLenPtr) != 1) {
           throw OpenSslException('EVP_DigestFinal_ex failed');
        }
        
        return Uint8List.fromList(outPtr.cast<Uint8>().asTypedList(outLenPtr.value));
      } finally {
        bindings.EVP_MD_CTX_free(ctx);
      }
    } finally {
      arena.releaseAll();
    }
  }

  /// Calcula o HMAC dos dados usando o algoritmo e chave especificados.
  /// 
  /// [algorithmName]: Nome do algoritmo de hash (ex: 'sha256').
  /// [key]: Chave secreta.
  /// [data]: Dados para autenticar.
  Uint8List hmac(String algorithmName, Uint8List key, Uint8List data) {
     final arena = Arena();
     try {
       final namePtr = algorithmName.toNativeUtf8(allocator: arena);
       final md = bindings.EVP_get_digestbyname(namePtr.cast());
       if (md == nullptr) throw OpenSslException('Unknown digest algorithm: $algorithmName');
       
       final ctx = bindings.HMAC_CTX_new();
       if (ctx == nullptr) throw OpenSslException('Failed to create HMAC_CTX');
       
       try {
         final keyPtr = arena<UnsignedChar>(key.length);
         keyPtr.cast<Uint8>().asTypedList(key.length).setAll(0, key);
         
         if (bindings.HMAC_Init_ex(ctx, keyPtr.cast(), key.length, md, nullptr) != 1) {
           throw OpenSslException('HMAC_Init_ex failed');
         }
         
         final dataPtr = arena<UnsignedChar>(data.length);
         dataPtr.cast<Uint8>().asTypedList(data.length).setAll(0, data);
         
         if (bindings.HMAC_Update(ctx, dataPtr.cast(), data.length) != 1) {
           throw OpenSslException('HMAC_Update failed');
         }
         
         final outPtr = arena<UnsignedChar>(128);
         final outLenPtr = arena<UnsignedInt>(1);
         
         if (bindings.HMAC_Final(ctx, outPtr, outLenPtr) != 1) {
            throw OpenSslException('HMAC_Final failed');
         }
         
         return Uint8List.fromList(outPtr.cast<Uint8>().asTypedList(outLenPtr.value));
       } finally {
         bindings.HMAC_CTX_free(ctx);
       }
     } finally {
       arena.releaseAll();
     }
  }

  /// Computes shared secret (ECDH) between [privateKey] and [peerPublicKey].
  Uint8List computeSharedSecret(EvpPkey privateKey, EvpPkey peerPublicKey) {
    // 1. Create context from the private key
    // EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
    final ctx = bindings.EVP_PKEY_CTX_new(privateKey.handle, nullptr);
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_PKEY_CTX');
    
    try {
      // 2. Init derive
      if (bindings.EVP_PKEY_derive_init(ctx) <= 0) {
        throw OpenSslException('EVP_PKEY_derive_init failed');
      }
      
      // 3. Set peer
      if (bindings.EVP_PKEY_derive_set_peer(ctx, peerPublicKey.handle) <= 0) {
        throw OpenSslException('EVP_PKEY_derive_set_peer failed');
      }
      
      // 4. Determine buffer length
      final lenPtr = calloc<Size>(); // size_t*
      if (bindings.EVP_PKEY_derive(ctx, nullptr, lenPtr) <= 0) {
        calloc.free(lenPtr);
         throw OpenSslException('EVP_PKEY_derive (length) failed');
      }
      
      // 5. Derive
      final len = lenPtr.value;
      final secretPtr = calloc<Uint8>(len);
      
      try {
        if (bindings.EVP_PKEY_derive(ctx, secretPtr.cast(), lenPtr) <= 0) {
          throw OpenSslException('EVP_PKEY_derive failed');
        }
        return Uint8List.fromList(secretPtr.asTypedList(len));
      } finally {
        calloc.free(secretPtr);
        calloc.free(lenPtr);
      }
    } finally {
      bindings.EVP_PKEY_CTX_free(ctx);
    }
  }
}
