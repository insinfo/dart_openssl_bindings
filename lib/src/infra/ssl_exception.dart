import 'dart:async';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';

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
  static void checkError(OpenSslFfi lib,
      {String? function, bool throwIfError = true}) {
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
  static void clearError(OpenSslFfi lib) {
    while (lib.ERR_get_error() != 0) {}
  }
}

class OpenSslLoadException implements Exception {
  final String message;
  OpenSslLoadException(this.message);
  @override
  String toString() => 'OpenSslLoadException: $message';
}

/// This [Exception] is thrown when a DTLS related error occurs.
class OpenSslDtlsException implements Exception {
  /// Constructor.
  OpenSslDtlsException(this.message);

  /// The error message of this [OpenSslDtlsException].
  final String message;

  @override
  String toString() => "OpenSslDtlsException: $message";
}

/// A [OpenSslDtlsException] that is thrown when a DTLS handshake fails.
class OpenSslDtlsHandshakeException extends OpenSslDtlsException {
  /// Constructor.
  OpenSslDtlsHandshakeException(super.message);

  @override
  String toString() => "OpenSslDtlsHandshakeException: $message";
}

/// [OpenSslDtlsException] that indicates that a timeout has occured.
class OpenSslDtlsTimeoutException extends OpenSslDtlsException
    implements TimeoutException {
  /// Constructor.
  OpenSslDtlsTimeoutException(super.message, this.duration);

  @override
  final Duration duration;

  @override
  String toString() => "OpenSslDtlsTimeoutException after $duration: $message";
}

/// This [Exception] is thrown when a TLS related error occurs.
class OpenSslTlsException implements Exception {
  /// Constructor.
  OpenSslTlsException(this.message);

  /// The error message.
  final String message;

  @override
  String toString() => "OpenSslTlsException: $message";
}

/// Thrown when a TLS handshake fails.
class OpenSslHandshakeException extends OpenSslTlsException {
  /// Constructor.
  OpenSslHandshakeException(super.message);

  @override
  String toString() => "OpenSslHandshakeException: $message";
}
