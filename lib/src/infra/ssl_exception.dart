import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'openssl_lib.dart';

/// Exception thrown when an OpenSSL error occurs.
class OpenSslException implements Exception {
  final String message;
  final int errorCode;
  final String? function;

  OpenSslException(this.message, [this.errorCode = 0, this.function]);

  @override
  String toString() {
    var msg = 'OpenSslException: $message';
    if (errorCode != 0) msg += ' (code: $errorCode)';
    if (function != null) msg += ' in $function';
    return msg;
  }

  /// Checks the OpenSSL error queue. If there are errors, throws an SslException.
  /// Should be called after a C function returns a failure code.
  static void checkError({String? function, bool throwIfError = true}) {
    final lib = OpenSslLib.instance;
    // Get the most recent error
    final code = lib.ERR_get_error();
    
    if (code != 0) {
      if (!throwIfError) return;
      
      final buffer = calloc<Char>(256);
      try {
        lib.ERR_error_string(code, buffer);
        final msg = buffer.cast<Utf8>().toDartString();
        throw OpenSslException(msg, code, function);
      } finally {
        calloc.free(buffer);
      }
    }
  }
  
  /// Clears the error queue.
  static void clearError() {
     while(OpenSslLib.instance.ERR_get_error() != 0) {}
  }
}
