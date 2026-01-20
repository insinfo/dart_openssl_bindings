import 'dart:ffi';
import 'package:meta/meta.dart';

/// Base class for all OpenSSL objects that hold a native pointer
/// and require automatic memory management via NativeFinalizer.
abstract class SslObject<T extends NativeType> implements Finalizable {
  final Pointer<T> _ptr;
  
  // We use a specific Finalizer per subclass usually, or pass it in.
  // But here we can provide a method to attach.
  
  SslObject(this._ptr);

  Pointer<T> get handle {
    if (_ptr == nullptr) {
      throw StateError('Attempt to use a null pointer for ${runtimeType}');
    }
    return _ptr;
  }

  /// Returns true if the underlying pointer is null.
  bool get isNull => _ptr == nullptr;

  /// Attaches this Dart object to the native pointer so that [finalizer]
  /// calls [freeFunc] on [_ptr] when this object is GC'd.
  @protected
  void attachFinalizer(NativeFinalizer finalizer, Pointer<Void> token, {int? externalSize}) {
    finalizer.attach(this, token, detach: this, externalSize: externalSize);
  }

  /// Helper to check OpenSSL result codes.
  /// Standard OpenSSL convention: 1 is success, 0 is failure (e.g. signature verify), <0 is error.
  static void checkCode(int result, {String msg = 'Operation failed'}) {
    if (result <= 0) {
      // In a real implementation we would call ERR_get_error() here.
      throw Exception('OpenSSL Error: $msg (Code: $result)');
    }
  }

  /// Manually dispose the native object. 
  /// Note: The Finalizer must support detachment if we want to do this safely, 
  /// but NativeFinalizer automatically handles detached objects if we passed `detach: this`.
  void dispose() {
     // This base class doesn't enforce how to free, 
     // but subclasses can implement strict dispose if they want deterministic cleanup.
  }
}
