import 'dart:ffi';

import '../api/openssl_context.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';
import 'x509_certificate.dart';

/// Wrapper around OpenSSL X509_STORE.
/// Used to hold trusted CA certificates for verification.
class X509Store extends SslObject<X509_STORE> {
  final OpenSslContext _context;
  late final NativeFinalizer _finalizer;

  X509Store(Pointer<X509_STORE> ptr, this._context) : super(ptr) {
    // Note: We lookup the native function pointer for the finalizer.
    // The type argument <Void Function(...)> matches the C signature in Dart FFI typedefs.
    final freePtr = _context.lookup<Void Function(Pointer<X509_STORE>)>('X509_STORE_free');
    _finalizer = NativeFinalizer(freePtr.cast());
     _finalizer.attach(this, ptr.cast(), detach: this);
  }

  /// Creates a new empty X509 Certificate Store.
  factory X509Store.create(OpenSslContext context) {
    final ptr = context.bindings.X509_STORE_new();
    if (ptr == nullptr) {
      throw OpenSslException('Failed to create X509_STORE');
    }
    return X509Store(ptr, context);
  }

  /// Adds a trusted certificate into the store.
  void addCert(X509Certificate cert) {
    // X509_STORE_add_cert internally increments the ref count of the cert,
    // so the store effectively takes shared ownership.
    final result = _context.bindings.X509_STORE_add_cert(handle, cert.handle);
    if (result != 1) {
       // We might want to check ERR_get_error, but for now simple exception.
       throw OpenSslException('Failed to add certificate to store');
    }
  }
}
