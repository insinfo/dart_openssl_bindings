import 'dart:ffi';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

import 'package:ffi/ffi.dart'; // import ffi/ffi

/// Wrapper around OpenSSL EVP_PKEY (Private/Public Key).
class EvpPkey extends SslObject<EVP_PKEY> {
  final OpenSSL _context;
  
  // O finalizer precisa ser construído com o endereço da função free DAQUELA instância/dll.
  // No caso de múltiplas DLLs carregadas, cada uma tem seu endereço.
  // late final NativeFinalizer _finalizer;

  EvpPkey(Pointer<EVP_PKEY> ptr, this._context) : super(ptr) {
    // Buscamos o endereço de free no contexto
    // final freePtr = _context.lookup<Void Function(Pointer<EVP_PKEY>)>('EVP_PKEY_free');
    // _finalizer = NativeFinalizer(freePtr.cast());
    //  _finalizer.attach(this, ptr.cast(), detach: this);
  }

  /// Exports Private Key to PEM format.
  /// 
  /// If [password] is provided, utilizes PKCS#8 encryption (AES-256-CBC).
  /// Otherwise exports as unencrypted PKCS#8 or traditional format depending on Key Type.
  String toPrivateKeyPem({String? password}) {
    final bio = _context.createBio();
    Pointer<Char> pwdPtr = nullptr;
    Pointer<EVP_CIPHER> cipher = nullptr;
    
    if (password != null) {
      pwdPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
      // PKCS#8 standard recommends AES-256-CBC
      cipher = _context.bindings.EVP_aes_256_cbc();
    }

    try {
      int result;
      if (password != null) {
         // Use PKCS#8 for encrypted keys (Standard)
         // int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
         //                                  char *kstr, int klen,
         //                                  pem_password_cb *cb, void *u);
         result = _context.bindings.PEM_write_bio_PKCS8PrivateKey(
            bio,
            handle,
            cipher,
            pwdPtr, // char* kstr
            0,      // klen - 0 means let OpenSSL calculate strlen
            nullptr,
            nullptr
         );
      } else {
         // For unencrypted, PEM_write_bio_PrivateKey is generally fine and widely compatible.
         // It produces "-----BEGIN PRIVATE KEY-----" (PKCS#8) for modern OpenSSL defaults.
         result = _context.bindings.PEM_write_bio_PrivateKey(
            bio, 
            handle, 
            nullptr, 
            nullptr, 
            0, 
            nullptr, 
            nullptr
         );
      }
      
      if (result != 1) throw OpenSslException('Failed to write private key to PEM');
      return _context.bioToString(bio);
    } finally {
      if (pwdPtr != nullptr) calloc.free(pwdPtr);
      _context.freeBio(bio);
    }
  }

  /// Exports Public Key to PEM format (SubjectPublicKeyInfo).
  String toPublicKeyPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_PUBKEY(bio, handle);
      if (result != 1) throw OpenSslException('Failed to write public key to PEM');
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }
}
