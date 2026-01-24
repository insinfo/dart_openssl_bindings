import 'dart:ffi';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

/// Wrapper around OpenSSL X509_REQ (Certificate Signing Request).
class X509Request extends SslObject<X509_REQ> {
  final OpenSSL _context;
  // late final NativeFinalizer _finalizer;

  X509Request(Pointer<X509_REQ> ptr, this._context) : super(ptr) {
    // final freePtr = _context.lookup<Void Function(Pointer<X509_REQ>)>('X509_REQ_free');
    // _finalizer = NativeFinalizer(freePtr.cast());
    // attachFinalizer(_finalizer, ptr.cast());
  }

  void dispose() {
    // _finalizer.detach(this);
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
}
