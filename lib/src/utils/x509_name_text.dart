import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../generated/ffi.dart';

const int _bioCtrlPending = 10;

/// Renders an X509_NAME as a DN string, the way `X509_NAME_print_ex` writes it
/// with no indentation and no flags (e.g. "C=BR, O=ICP-Brasil, CN=...").
///
/// Returns an empty string for `nullptr` or when OpenSSL writes nothing.
String x509NameToString(OpenSslFfi bindings, Pointer<X509_NAME> namePtr) {
  if (namePtr == nullptr) return '';

  final bio = bindings.BIO_new(bindings.BIO_s_mem());
  if (bio == nullptr) return '';

  try {
    bindings.X509_NAME_print_ex(bio, namePtr, 0, 0);

    final len = bindings.BIO_ctrl(bio, _bioCtrlPending, 0, nullptr);
    if (len <= 0) return '';

    final buffer = calloc<Uint8>(len + 1);
    try {
      bindings.BIO_read(bio, buffer.cast(), len);
      return buffer.cast<Utf8>().toDartString(length: len);
    } finally {
      calloc.free(buffer);
    }
  } finally {
    bindings.BIO_free(bio);
  }
}
