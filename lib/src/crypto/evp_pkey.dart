import 'dart:convert';
import 'dart:ffi';

import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

import 'package:ffi/ffi.dart'; // import ffi/ffi

Pointer<Uint8> _allocUtf8z(String s) {
  final bytes = utf8.encode(s);
  final p = calloc<Uint8>(bytes.length + 1);
  p.asTypedList(bytes.length).setAll(0, bytes);
  p[bytes.length] = 0; 
  return p;
}

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
    Pointer<Uint8>? pw;
    Pointer<EVP_CIPHER> cipher = nullptr;
    int pwLen = 0;
    
    if (password != null) {
      final bytes = utf8.encode(password);
      pwLen = bytes.length;
      pw = _allocUtf8z(password);
      // PKCS#8 standard recommends AES-256-CBC
      cipher = _context.bindings.EVP_aes_256_cbc();
    }

    try {
      int result;
      if (password != null) {
         // Use PKCS#8 for encrypted keys (Standard)
         result = _context.bindings.PEM_write_bio_PKCS8PrivateKey(
            bio,
            handle,
            cipher,
            pw!.cast(), // char* kstr
            pwLen,      // klen - actual password length
            nullptr,
            nullptr
         );
      } else {
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
      if (pw != null) calloc.free(pw);
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

  /// Releases the underlying EVP_PKEY structure.
  void dispose() {
    _context.bindings.EVP_PKEY_free(handle);
  }
}
