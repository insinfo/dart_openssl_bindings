import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';
import '../utils/x509_name_text.dart';

/// Wrapper around OpenSSL X509_REQ (Certificate Signing Request).
class X509Request extends SslObject<X509_REQ> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  X509Request(Pointer<X509_REQ> ptr, this._context) : super(ptr) {
    final freePtr =
        _context.lookup<Void Function(Pointer<X509_REQ>)>('X509_REQ_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, ptr.cast(), detach: this);
  }

  void dispose() {
    _finalizer.detach(this);
    _context.bindings.X509_REQ_free(handle);
  }

  /// Exports CSR to PEM format.
  String toPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_X509_REQ(bio, handle);
      if (result != 1) throw OpenSslException('Failed to write CSR to PEM');
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }

  /// Exports CSR to DER bytes.
  Uint8List toDer() {
    final len = _context.bindings.i2d_X509_REQ(handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get CSR DER length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_X509_REQ(handle, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode CSR to DER');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  /// CSR version: 1 for the only version PKCS#10 defines (the encoded value
  /// is zero-based).
  int get version => _context.bindings.X509_REQ_get_version(handle) + 1;

  /// Subject DN requested by the CSR, in the same format as
  /// [X509Certificate.subject].
  String get subject {
    return x509NameToString(
      _context.bindings,
      _context.bindings.X509_REQ_get_subject_name(handle),
    );
  }

  /// Public key the CSR asks to have certified.
  ///
  /// Returns a fresh [EvpPkey] on every call; the caller owns it and should
  /// call `dispose()` when done.
  EvpPkey get publicKey {
    final pkey = _context.bindings.X509_REQ_get_pubkey(handle);
    if (pkey == nullptr) {
      throw OpenSslException('X509_REQ_get_pubkey failed');
    }
    return EvpPkey(pkey, _context);
  }

  /// Verifies the CSR signature.
  ///
  /// With no [key] this checks the self-signature — the proof that whoever
  /// sent the CSR holds the private key for the public key inside it, which
  /// is what a CA checks before issuing. Pass [key] to verify against a
  /// different public key instead.
  bool verifySignature([EvpPkey? key]) {
    final ownKey = key == null ? publicKey : null;
    try {
      final verifyKey = key ?? ownKey!;
      return _context.bindings.X509_REQ_verify(handle, verifyKey.handle) == 1;
    } finally {
      ownKey?.dispose();
    }
  }
}
