import 'dart:ffi'; 
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';

const int BIO_CTRL_PENDING = 10;

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
  /// Returns 1 for V1, 3 for V3.
  int get version {
     final v = _context.bindings.X509_get_version(handle);
     return v + 1;
  }

  /// Gets the Subject DN as a string (e.g. "C=BR, O=ICP-Brasil, ...").
  String get subject {
    final namePtr = _context.bindings.X509_get_subject_name(handle);
    if (namePtr == nullptr) return '';
    return _x509NameToString(namePtr);
  }

  /// Gets the Issuer DN as a string.
  String get issuer {
    final namePtr = _context.bindings.X509_get_issuer_name(handle);
    if (namePtr == nullptr) return '';
    return _x509NameToString(namePtr);
  }

  String _x509NameToString(Pointer<X509_NAME> namePtr) {
    if (namePtr == nullptr) return '';
    
    final bio = _context.bindings.BIO_new(_context.bindings.BIO_s_mem());
    if (bio == nullptr) return '';
    
    try {
      // XN_FLAG_RFC2253 (0) -> C=BR,O=... (comma separated)
      // XN_FLAG_ONELINE (~0) ?
      // Use XN_FLAG_SEP_COMMA_PLUS (0x10000) | XN_FLAG_DN_REV (0x2000000) for RFC2253-like
      // Let's use simple RFC2253 format which is standard
      _context.bindings.X509_NAME_print_ex(bio, namePtr, 0, 0); // 0 indent, 0 flags (RFC2253?)
      
      final len = _context.bindings.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr);
      if (len <= 0) return '';
      
      final buffer = calloc<Uint8>(len + 1);
      try {
        _context.bindings.BIO_read(bio, buffer.cast(), len);
        return buffer.cast<Utf8>().toDartString(length: len);
      } finally {
        calloc.free(buffer);
      }
    } finally {
      _context.bindings.BIO_free(bio);
    }
  }

  /// Gets the Serial Number as a decimal string.
  String get serialNumber {
    final asn1Int = _context.bindings.X509_get_serialNumber(handle);
    if (asn1Int == nullptr) return '';
    
    final bn = _context.bindings.ASN1_INTEGER_to_BN(asn1Int, nullptr);
    if (bn == nullptr) return '';
    
    try {
      final decPtr = _context.bindings.BN_bn2dec(bn);
      if (decPtr == nullptr) return '';
      
      try {
        return decPtr.cast<Utf8>().toDartString();
      } finally {
        // Safe to call CRYPTO_free on OpenSSL allocated strings
        _context.bindings.CRYPTO_free(decPtr.cast(), nullptr, 0); 
      }
    } finally {
      _context.bindings.BN_free(bn);
    }
  }

  /// Valid NotBefore date (Start Date).
  DateTime? get notBefore {
    final timePtr = _context.bindings.X509_getm_notBefore(handle);
    return _parseAsn1Time(timePtr);
  }

  /// Valid NotAfter date (End Date).
  DateTime? get notAfter {
    final timePtr = _context.bindings.X509_getm_notAfter(handle);
    return _parseAsn1Time(timePtr);
  }

  DateTime? _parseAsn1Time(Pointer<ASN1_TIME> timePtr) {
    if (timePtr == nullptr) return null;
    
    final tmPtr = calloc<tm>();
    try {
      final success = _context.bindings.ASN1_TIME_to_tm(timePtr, tmPtr);
      if (success != 1) return null;

      final t = tmPtr.ref;
      // tm_year is years since 1900
      final year = t.tm_year + 1900;
      // tm_mon is 0-11
      final month = t.tm_mon + 1;
      
      return DateTime.utc(
        year,
        month,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
      );
    } finally {
      calloc.free(tmPtr);
    }
  }
}

