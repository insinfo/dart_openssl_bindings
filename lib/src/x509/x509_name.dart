import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

/// Wrapper around OpenSSL X509_NAME.
/// Represents the Subject or Issuer of a certificate.
class X509Name extends SslObject<X509_NAME> {
  final OpenSSL _context;
  // Does X509_NAME need a finalizer?
  // If it's part of an X509 struct (via get_subject_name), the X509 struct owns it.
  // If we create it standalone (X509_NAME_new), we own it.
  // For now, we will assume we mostly use this as a view or part of Builder which might create it.
  // But strictly, if we create it, we should free it.
  // However, X509_set_subject_name CAUSES A COPY. So if we create one to set it, we must free our copy.
  
  late final NativeFinalizer _finalizer;
  bool _isOwned = false;

  X509Name(Pointer<X509_NAME> ptr, this._context, {bool isOwned = false}) : super(ptr) {
    _isOwned = isOwned;
    if (_isOwned) {
      final freePtr = _context.lookup<Void Function(Pointer<X509_NAME>)>('X509_NAME_free');
      _finalizer = NativeFinalizer(freePtr.cast());
      attachFinalizer(_finalizer, ptr.cast());
    }
  }

  /// Adds a text entry to the name.
  /// [field] is the short name (e.g., "CN", "O", "C", "OU").
  /// [value] is the value.
  void addEntry(String field, String value) {
    final fieldPtr = field.toNativeUtf8();
    final valuePtr = value.toNativeUtf8();
    try {
      // MBSTRING_UTF8 = 0x1000
      final result = _context.bindings.X509_NAME_add_entry_by_txt(
        handle,
        fieldPtr.cast(),
        0x1000, // MBSTRING_UTF8
        valuePtr.cast(),
        -1,
        -1,
        0
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
