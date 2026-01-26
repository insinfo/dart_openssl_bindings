import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';

/// Wrapper around OpenSSL X509_CRL.
class X509Crl extends SslObject<X509_CRL> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  X509Crl(Pointer<X509_CRL> ptr, this._context) : super(ptr) {
    final freePtr =
        _context.lookup<Void Function(Pointer<X509_CRL>)>('X509_CRL_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, ptr.cast(), detach: this);
  }

  void dispose() {
    _finalizer.detach(this);
    _context.bindings.X509_CRL_free(handle);
  }

  /// Encodes CRL to PEM.
  String toPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_X509_CRL(bio, handle);
      if (result != 1) {
        throw OpenSslException('Failed to write CRL to PEM');
      }
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }

  /// Encodes CRL to DER bytes.
  Uint8List toDer() {
    final len = _context.bindings.i2d_X509_CRL(handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get CRL DER length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_X509_CRL(handle, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode CRL to DER');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }
}