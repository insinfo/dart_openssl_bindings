import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../../infra/ssl_exception.dart';

// Constants for EVP_CIPHER_CTX_ctrl (from evac.h / evp.h)
const int EVP_CTRL_GCM_SET_IVLEN = 0x9;
const int EVP_CTRL_GCM_GET_TAG = 0x10;
const int EVP_CTRL_GCM_SET_TAG = 0x11;
const int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
const int EVP_CTRL_AEAD_GET_TAG = 0x10;
const int EVP_CTRL_AEAD_SET_TAG = 0x11;

/// Mixin for Symmetric Encryption operations (AES).
mixin CipherMixin on OpenSslContext {
  
  /// Encrypts [data] using AES-256-GCM.
  /// 
  /// Returns a map containing:
  /// - 'ciphertext': Uint8List
  /// - 'tag': Uint8List (Authentication Tag, usually 16 bytes)
  /// 
  /// [key] must be 32 bytes.
  /// [iv] (Initialization Vector) should be unique (typically 12 bytes).
  /// [aad] (Additional Authenticated Data) is optional.
  Map<String, Uint8List> aes256GcmEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
    Uint8List? aad,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes for AES-256');
    // GCM standard IV is 96 bits (12 bytes), but can be other sizes.
    
    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    // Output buffer can be at most input size + block size (though GCM matches input size)
    final outPtr = calloc<Uint8>(data.length + 16); 
    final outLen = calloc<Int>();
    
    try {
      // 1. Init Cipher
      final cipher = bindings.EVP_aes_256_gcm();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      // 2. Set IV Length (if not default 12)
      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      // 3. Init Key and IV
      if (bindings.EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key and IV');
      }

      // 4. Provide AAD (Optional)
      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
           if (bindings.EVP_EncryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
             throw OpenSslException('Failed to set AAD');
           }
        } finally {
          calloc.free(aadPtr);
        }
      }

      // 5. Encrypt Data
      final inPtr = calloc<Uint8>(data.length);
      inPtr.asTypedList(data.length).setAll(0, data);
      
      int totalLen = 0;
      
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
           throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      // 6. Finalize
      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;

      // 7. Get Tag
      final tagPtr = calloc<Uint8>(16);
      try {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagPtr.cast()) != 1) {
           throw OpenSslException('Failed to get GCM Tag');
        }
        
        final ciphertext = Uint8List.fromList(outPtr.asTypedList(totalLen));
        final tag = Uint8List.fromList(tagPtr.asTypedList(16));
        
        return {
          'ciphertext': ciphertext,
          'tag': tag,
        };
      } finally {
        calloc.free(tagPtr);
      }

    } finally { // Cleanup
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Encrypts [data] using AES-128-GCM.
  Map<String, Uint8List> aes128GcmEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
    Uint8List? aad,
  }) {
    if (key.length != 16) throw ArgumentError('Key must be 16 bytes for AES-128');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final outPtr = calloc<Uint8>(data.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_128_gcm();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      if (bindings.EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key and IV');
      }

      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
          if (bindings.EVP_EncryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
            throw OpenSslException('Failed to set AAD');
          }
        } finally {
          calloc.free(aadPtr);
        }
      }

      final inPtr = calloc<Uint8>(data.length);
      inPtr.asTypedList(data.length).setAll(0, data);

      int totalLen = 0;
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;

      final tagPtr = calloc<Uint8>(16);
      try {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagPtr.cast()) != 1) {
          throw OpenSslException('Failed to get GCM Tag');
        }

        return {
          'ciphertext': Uint8List.fromList(outPtr.asTypedList(totalLen)),
          'tag': Uint8List.fromList(tagPtr.asTypedList(16)),
        };
      } finally {
        calloc.free(tagPtr);
      }
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using AES-256-GCM.
  /// Throws [OpenSslException] if authentication fails (Tag mismatch).
  Uint8List aes256GcmDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes');
    if (tag.length != 16) throw ArgumentError('Tag must be 16 bytes');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);
    
    final tagPtr = calloc<Uint8>(tag.length);
    tagPtr.asTypedList(tag.length).setAll(0, tag);

    final outPtr = calloc<Uint8>(ciphertext.length + 16); 
    final outLen = calloc<Int>();

    try {
       // 1. Init Cipher
      final cipher = bindings.EVP_aes_256_gcm();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      // 2. Set IV Length
      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      // 3. Init Key and IV
      if (bindings.EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key/IV');
      }

      // 4. Provide AAD
      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
           if (bindings.EVP_DecryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
             throw OpenSslException('Failed to set AAD');
           }
        } finally {
          calloc.free(aadPtr);
        }
      }

      // 5. Decrypt Data
      final inPtr = calloc<Uint8>(ciphertext.length);
      inPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);
      
      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      // 6. Set Expected Tag (Validation)
      if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagPtr.cast()) != 1) {
        throw OpenSslException('Failed to set expected Tag');
      }

      // 7. Finalize (Checks Tag)
      final ret = bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen);
      
      if (ret <= 0) {
        throw OpenSslException('Decryption failed (Tag mismatch or bad data)');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));

    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      calloc.free(tagPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using AES-128-GCM.
  Uint8List aes128GcmDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    if (key.length != 16) throw ArgumentError('Key must be 16 bytes');
    if (tag.length != 16) throw ArgumentError('Tag must be 16 bytes');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final tagPtr = calloc<Uint8>(tag.length);
    tagPtr.asTypedList(tag.length).setAll(0, tag);

    final outPtr = calloc<Uint8>(ciphertext.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_128_gcm();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      if (bindings.EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key/IV');
      }

      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
          if (bindings.EVP_DecryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
            throw OpenSslException('Failed to set AAD');
          }
        } finally {
          calloc.free(aadPtr);
        }
      }

      final inPtr = calloc<Uint8>(ciphertext.length);
      inPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagPtr.cast()) != 1) {
        throw OpenSslException('Failed to set expected Tag');
      }

      final ret = bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen);
      if (ret <= 0) {
        throw OpenSslException('Decryption failed (Tag mismatch or bad data)');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      calloc.free(tagPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Encrypts [data] using AES-256-CBC with PKCS#7 padding.
  ///
  /// [key] must be 32 bytes and [iv] must be 16 bytes.
  Uint8List aes256CbcEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes for AES-256-CBC');
    }
    if (iv.length != 16) {
      throw ArgumentError('IV must be 16 bytes for AES-256-CBC');
    }

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_CIPHER_CTX');
    }

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    // Output buffer needs at most input length + block size (16 bytes).
    final outPtr = calloc<Uint8>(data.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_256_cbc();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(data.length);
      inPtr.asTypedList(data.length).setAll(0, data);

      int totalLen = 0;
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Encrypts [data] using AES-128-CBC with PKCS#7 padding.
  Uint8List aes128CbcEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 16) {
      throw ArgumentError('Key must be 16 bytes for AES-128-CBC');
    }
    if (iv.length != 16) {
      throw ArgumentError('IV must be 16 bytes for AES-128-CBC');
    }

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final outPtr = calloc<Uint8>(data.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_128_cbc();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(data.length);
      inPtr.asTypedList(data.length).setAll(0, data);

      int totalLen = 0;
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using AES-256-CBC with PKCS#7 padding.
  ///
  /// [key] must be 32 bytes and [iv] must be 16 bytes.
  Uint8List aes256CbcDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes for AES-256-CBC');
    }
    if (iv.length != 16) {
      throw ArgumentError('IV must be 16 bytes for AES-256-CBC');
    }

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_CIPHER_CTX');
    }

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final outPtr = calloc<Uint8>(ciphertext.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_256_cbc();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(ciphertext.length);
      inPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      final ret = bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen);
      if (ret <= 0) {
        throw OpenSslException('EVP_DecryptFinal_ex failed (bad padding or data)');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using AES-128-CBC with PKCS#7 padding.
  Uint8List aes128CbcDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 16) {
      throw ArgumentError('Key must be 16 bytes for AES-128-CBC');
    }
    if (iv.length != 16) {
      throw ArgumentError('IV must be 16 bytes for AES-128-CBC');
    }

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final outPtr = calloc<Uint8>(ciphertext.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_aes_128_cbc();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(ciphertext.length);
      inPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_DecryptFinal_ex failed');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Encrypts [data] using ChaCha20-Poly1305 (AEAD).
  Map<String, Uint8List> chacha20Poly1305Encrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
    Uint8List? aad,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes for ChaCha20-Poly1305');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final outPtr = calloc<Uint8>(data.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_chacha20_poly1305();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      if (bindings.EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key and IV');
      }

      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
          if (bindings.EVP_EncryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
            throw OpenSslException('Failed to set AAD');
          }
        } finally {
          calloc.free(aadPtr);
        }
      }

      final inPtr = calloc<Uint8>(data.length);
      inPtr.asTypedList(data.length).setAll(0, data);

      int totalLen = 0;
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;

      final tagPtr = calloc<Uint8>(16);
      try {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tagPtr.cast()) != 1) {
          throw OpenSslException('Failed to get Poly1305 Tag');
        }

        return {
          'ciphertext': Uint8List.fromList(outPtr.asTypedList(totalLen)),
          'tag': Uint8List.fromList(tagPtr.asTypedList(16)),
        };
      } finally {
        calloc.free(tagPtr);
      }
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using ChaCha20-Poly1305 (AEAD).
  Uint8List chacha20Poly1305Decrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes for ChaCha20-Poly1305');
    if (tag.length != 16) throw ArgumentError('Tag must be 16 bytes');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final ivPtr = calloc<Uint8>(iv.length);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final tagPtr = calloc<Uint8>(tag.length);
    tagPtr.asTypedList(tag.length).setAll(0, tag);

    final outPtr = calloc<Uint8>(ciphertext.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_chacha20_poly1305();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      if (iv.length != 12) {
        if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.length, nullptr) != 1) {
          throw OpenSslException('Failed to set IV length');
        }
      }

      if (bindings.EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('Failed to set Key/IV');
      }

      if (aad != null && aad.isNotEmpty) {
        final aadPtr = calloc<Uint8>(aad.length);
        aadPtr.asTypedList(aad.length).setAll(0, aad);
        try {
          if (bindings.EVP_DecryptUpdate(ctx, nullptr, outLen, aadPtr.cast(), aad.length) != 1) {
            throw OpenSslException('Failed to set AAD');
          }
        } finally {
          calloc.free(aadPtr);
        }
      }

      final inPtr = calloc<Uint8>(ciphertext.length);
      inPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tagPtr.cast()) != 1) {
        throw OpenSslException('Failed to set expected Tag');
      }

      final ret = bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen);
      if (ret <= 0) {
        throw OpenSslException('Decryption failed (Tag mismatch or bad data)');
      }
      totalLen += outLen.value;

      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      calloc.free(tagPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Encrypts [data] using ChaCha20 (stream cipher).
  Uint8List chacha20Encrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes for ChaCha20');
    if (iv.length != 16) throw ArgumentError('IV must be 16 bytes for ChaCha20');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length)..asTypedList(key.length).setAll(0, key);
    final ivPtr = calloc<Uint8>(iv.length)..asTypedList(iv.length).setAll(0, iv);
    final outPtr = calloc<Uint8>(data.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_chacha20();
      if (bindings.EVP_EncryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_EncryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(data.length)..asTypedList(data.length).setAll(0, data);
      int totalLen = 0;
      try {
        if (bindings.EVP_EncryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), data.length) != 1) {
          throw OpenSslException('EVP_EncryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_EncryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_EncryptFinal_ex failed');
      }
      totalLen += outLen.value;
      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Decrypts [ciphertext] using ChaCha20 (stream cipher).
  Uint8List chacha20Decrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
  }) {
    if (key.length != 32) throw ArgumentError('Key must be 32 bytes for ChaCha20');
    if (iv.length != 16) throw ArgumentError('IV must be 16 bytes for ChaCha20');

    final ctx = bindings.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create EVP_CIPHER_CTX');

    final keyPtr = calloc<Uint8>(key.length)..asTypedList(key.length).setAll(0, key);
    final ivPtr = calloc<Uint8>(iv.length)..asTypedList(iv.length).setAll(0, iv);
    final outPtr = calloc<Uint8>(ciphertext.length + 16);
    final outLen = calloc<Int>();

    try {
      final cipher = bindings.EVP_chacha20();
      if (bindings.EVP_DecryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast()) != 1) {
        throw OpenSslException('EVP_DecryptInit_ex failed');
      }

      final inPtr = calloc<Uint8>(ciphertext.length)..asTypedList(ciphertext.length).setAll(0, ciphertext);
      int totalLen = 0;
      try {
        if (bindings.EVP_DecryptUpdate(ctx, outPtr.cast(), outLen, inPtr.cast(), ciphertext.length) != 1) {
          throw OpenSslException('EVP_DecryptUpdate failed');
        }
        totalLen = outLen.value;
      } finally {
        calloc.free(inPtr);
      }

      if (bindings.EVP_DecryptFinal_ex(ctx, (outPtr + totalLen).cast(), outLen) != 1) {
        throw OpenSslException('EVP_DecryptFinal_ex failed');
      }
      totalLen += outLen.value;
      return Uint8List.fromList(outPtr.asTypedList(totalLen));
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(keyPtr);
      calloc.free(ivPtr);
      bindings.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// Rijndael is AES. Alias for AES-128-CBC.
  Uint8List rijndael128CbcEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
  }) => aes128CbcEncrypt(data: data, key: key, iv: iv);

  /// Rijndael is AES. Alias for AES-128-CBC.
  Uint8List rijndael128CbcDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
  }) => aes128CbcDecrypt(ciphertext: ciphertext, key: key, iv: iv);

  /// Rijndael is AES. Alias for AES-256-CBC.
  Uint8List rijndael256CbcEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
  }) => aes256CbcEncrypt(data: data, key: key, iv: iv);

  /// Rijndael is AES. Alias for AES-256-CBC.
  Uint8List rijndael256CbcDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
  }) => aes256CbcDecrypt(ciphertext: ciphertext, key: key, iv: iv);

  /// Rijndael is AES. Alias for AES-128-GCM.
  Map<String, Uint8List> rijndael128GcmEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
    Uint8List? aad,
  }) => aes128GcmEncrypt(data: data, key: key, iv: iv, aad: aad);

  /// Rijndael is AES. Alias for AES-128-GCM.
  Uint8List rijndael128GcmDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) => aes128GcmDecrypt(ciphertext: ciphertext, key: key, iv: iv, tag: tag, aad: aad);

  /// Rijndael is AES. Alias for AES-256-GCM.
  Map<String, Uint8List> rijndael256GcmEncrypt({
    required Uint8List data,
    required Uint8List key,
    required Uint8List iv,
    Uint8List? aad,
  }) => aes256GcmEncrypt(data: data, key: key, iv: iv, aad: aad);

  /// Rijndael is AES. Alias for AES-256-GCM.
  Uint8List rijndael256GcmDecrypt({
    required Uint8List ciphertext,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) => aes256GcmDecrypt(ciphertext: ciphertext, key: key, iv: iv, tag: tag, aad: aad);
}
