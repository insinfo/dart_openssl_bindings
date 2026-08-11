import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';
import 'jwk.dart';

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
  late final NativeFinalizer _finalizer;

  EvpPkey(Pointer<EVP_PKEY> ptr, this._context) : super(ptr) {
    final freePtr = _context.lookup<Void Function(Pointer<EVP_PKEY>)>('EVP_PKEY_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, ptr.cast(), detach: this);
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

  /// Exports the public key as DER (SubjectPublicKeyInfo).
  ///
  /// The binary counterpart of [toPublicKeyPem], and what
  /// `OpenSSL.loadPublicKeyDer` reads back.
  Uint8List toPublicKeyDer() {
    final bindings = _context.bindings;

    // i2d with a null output asks for the length, then fills a buffer on the
    // second call — and advances the pointer it is given, which is why the
    // walking copy is kept separate from the one that gets freed.
    final length = bindings.i2d_PUBKEY(handle, nullptr);
    if (length <= 0) {
      throw OpenSslException('i2d_PUBKEY failed to size the public key');
    }

    final buffer = calloc<UnsignedChar>(length);
    final cursor = calloc<Pointer<UnsignedChar>>();
    try {
      cursor.value = buffer;
      final written = bindings.i2d_PUBKEY(handle, cursor);
      if (written != length) {
        throw OpenSslException('i2d_PUBKEY wrote $written of $length bytes');
      }
      return Uint8List.fromList(buffer.cast<Uint8>().asTypedList(length));
    } finally {
      calloc.free(buffer);
      calloc.free(cursor);
    }
  }

  /// Exports the public half of an RSA key as a JSON Web Key (RFC 7517).
  ///
  /// This is what a `jwks_uri` endpoint publishes, so relying parties can
  /// verify the tokens this key signs. [keyId], [algorithm] and [use] are
  /// metadata — typically `kid`, `RS256` and `sig` — and are omitted when null.
  ///
  /// ```dart
  /// final jwks = {'keys': [key.toPublicJwk(keyId: kid, algorithm: 'RS256', use: 'sig')]};
  /// ```
  ///
  /// Throws [FormatException] for anything other than an RSA key.
  Map<String, Object?> toPublicJwk({
    String? keyId,
    String? algorithm,
    String? use,
  }) =>
      rsaJwkFromSpkiDer(
        toPublicKeyDer(),
        keyId: keyId,
        algorithm: algorithm,
        use: use,
      );

  /// Releases the underlying EVP_PKEY structure.
  void dispose() {
    _finalizer.detach(this);
    _context.bindings.EVP_PKEY_free(handle);
  }
}
