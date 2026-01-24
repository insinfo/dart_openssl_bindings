import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

/// Wrapper around OpenSSL X509_NAME.
/// Represents the Subject or Issuer of a certificate.
///
/// This wrapper supports both owned and borrowed pointers.
/// If [isOwned] is true, the native pointer is freed when this object is GC'd or [dispose] is called.
/// If [isOwned] is false (e.g. returned by X509_get_subject_name), the pointer is NOT freed.
class X509Name extends SslObject<X509_NAME> {
  final OpenSSL _context;
  final bool _isOwned;
  NativeFinalizer? _finalizer;
  bool _isDisposed = false;

  X509Name(Pointer<X509_NAME> ptr, this._context, {bool isOwned = false}) 
      : _isOwned = isOwned, super(ptr) {
    if (_isOwned) {
      final freePtr = _context.lookup<Void Function(Pointer<X509_NAME>)>('X509_NAME_free');
      _finalizer = NativeFinalizer(freePtr.cast());
      // We attach the finalizer to 'this'.
      _finalizer!.attach(this, ptr.cast(), detach: this);
    }
  }

  /// Explicitly disposes the native resource if it is owned.
  /// After calling this, using the object is invalid.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    if (_isOwned) {
      _finalizer?.detach(this);
      _context.bindings.X509_NAME_free(handle);
    }
  }

  @override
  Pointer<X509_NAME> get handle {
    if (_isDisposed) {
      throw StateError('X509Name has been disposed.');
    }
    return super.handle;
  }

  /// Adds a text entry to the name.
  /// [field] is the short name (e.g., "CN", "O", "C", "OU").
  /// [value] is the value.
  void addEntry(String field, String value) {
    if (_isDisposed) {
      throw StateError('Cannot add entry to disposed X509Name');
    }
    final fieldPtr = field.toNativeUtf8(allocator: calloc);
    final valuePtr = value.toNativeUtf8(allocator: calloc);
    try {
      // MBSTRING_UTF8 = 0x1000
      // 0x1000 = MBSTRING_UTF8.
      final result = _context.bindings.X509_NAME_add_entry_by_txt(
        handle,
        fieldPtr.cast(),
        0x1000, 
        valuePtr.cast(),
        -1, // append
        -1, // loc
        0   // set
      );
      if (result != 1) {
         throw OpenSslException('Failed to add entry $field=$value to X509_NAME');
      }
    } finally {
      calloc.free(fieldPtr);
      calloc.free(valuePtr);
    }
  }
}
