import 'dart:ffi';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

/// Wrapper around OpenSSL EVP_PKEY (Private/Public Key).
class EvpPkey extends SslObject<EVP_PKEY> {
  final OpenSSL _context;
  
  // O finalizer precisa ser construído com o endereço da função free DAQUELA instância/dll.
  // No caso de múltiplas DLLs carregadas, cada uma tem seu endereço.
  late final NativeFinalizer _finalizer;

  EvpPkey(Pointer<EVP_PKEY> ptr, this._context) : super(ptr) {
    // Buscamos o endereço de free no contexto
    final freePtr = _context.lookup<Void Function(Pointer<EVP_PKEY>)>('EVP_PKEY_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    attachFinalizer(_finalizer, ptr.cast());
  }

  /// Exports Private Key to PEM format (PKCS#8 unencrypted).
  String toPrivateKeyPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_PrivateKey(
        bio, 
        handle, 
        nullptr, 
        nullptr, 
        0, 
        nullptr, 
        nullptr
      );
      
      if (result != 1) throw OpenSslException('Failed to write private key to PEM');
      return _context.bioToString(bio);
    } finally {
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
