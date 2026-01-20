import 'dart:ffi';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

/// Wrapper around OpenSSL X509 (Certificate).
class X509Certificate extends SslObject<X509> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  X509Certificate(Pointer<X509> ptr, this._context) : super(ptr) {
    final freePtr = _context.lookup<Void Function(Pointer<X509>)>('X509_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    attachFinalizer(_finalizer, ptr.cast());
  }

  /// Exports Certificate to PEM format.
  String toPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_X509(bio, handle);
      if (result != 1) throw OpenSslException('Failed to write certificate to PEM');
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }

  /// Gets the version of the certificate.
  /// Note: OpenSSL returns internal version (0 = V1, 1 = V2, 2 = V3).
  int get version {
    // X509_get_version is a macro or function depending on version, often confusing.
    // In our binding, we might not have exposed X509_get_version if it's a macro.
    // Let's check ffi.dart or use X509_get0_notBefore/etc.
    // Actually, `X509_get_version` maps to `ASN1_INTEGER_get(ptr->cert_info.version)`.
    // It's strictly defined as a macro in many versions.
    // We didn't add it to ffigen explicitly.
    // We can rely on `PEM` export for now or check if we have it.
    throw UnimplementedError('Version getter not implemented yet');
  }
}
