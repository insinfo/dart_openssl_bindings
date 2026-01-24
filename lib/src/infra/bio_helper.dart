import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'ssl_object.dart';
import 'ssl_exception.dart';
import '../generated/ffi.dart';
import '../api/openssl_context.dart';

const int BIO_CTRL_INFO = 3;

/// Wrapper around OpenSSL BIO (Basic Input/Output).
/// Used to bridge Dart Uint8List/String and OpenSSL's C IO.
class Bio extends SslObject<BIO> {
  final OpenSslContext _context;
  late final NativeFinalizer _finalizer;

  Bio._(this._context, Pointer<BIO> ptr) : super(ptr) {
    final freePtr = _context.lookup<Void Function(Pointer<BIO>)>('BIO_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    attachFinalizer(_finalizer, ptr.cast());
  }

  /// Creates a BIO from a memory buffer (Uint8List).
  factory Bio.fromBytes(OpenSslContext context, Uint8List bytes) {
    // We need to copy bytes to C memory because BIO_new_mem_buf can take a read-only buffer,
    // but if we want it to be safe, we might allocate.
    // However, BIO_new_mem_buf(buf, len) doesn't copy if len is positive? 
    // "If len is -1, then buf is assumed to be null terminated... If len is positive, then buf is used."
    // It creates a *read only* bio if the buffer is const, but usually it's better to create a writable memory bio and write to it
    // if we want to own the memory in the BIO.
    
    // Simplest: Create a memory BIO (writeable) and write data into it.
    final bio = context.bindings.BIO_new(context.bindings.BIO_s_mem());
    if (bio == nullptr) throw OpenSslException('Failed to create BIO');
    
    final wrapper = Bio._(context, bio);
    
    final buffer = calloc<Uint8>(bytes.length);
    try {
      buffer.asTypedList(bytes.length).setAll(0, bytes);
      final written = context.bindings.BIO_write(bio, buffer.cast(), bytes.length);
      if (written <= 0) {
        throw OpenSslException('Failed to write to BIO');
      }
    } finally {
      calloc.free(buffer);
    }
    
    return wrapper;
  }

  /// Creates a BIO from a String (utf8).
  factory Bio.fromString(OpenSslContext context, String text) {
    return Bio.fromBytes(context, Uint8List.fromList(text.codeUnits)); // Simple ASCII/UTF8
  }
  
  factory Bio.empty(OpenSslContext context) {
     final bio = context.bindings.BIO_new(context.bindings.BIO_s_mem());
     if (bio == nullptr) throw OpenSslException('Failed to create BIO');
     return Bio._(context, bio);
  }

  /// Reads the entire content of the BIO into a String.
  String toStringData() {
    final bytes = toBytes();
    return String.fromCharCodes(bytes);
  }

  /// Reads the entire content of the BIO into Uint8List.
  Uint8List toBytes() {
    final pp = calloc<Pointer<Char>>();
    try {
      // BIO_get_mem_data sets pp to verify the internal buffer and returns length.
      // NOTE: This usually only works for memory BIOs.
      final len = _context.bindings.BIO_ctrl(handle, BIO_CTRL_INFO, 0, pp.cast());
      if (len < 0) {
         throw OpenSslException('BIO_ctrl failed to get data');
      }
      
      final charPtr = pp.value;
      if (charPtr == nullptr || len == 0) return Uint8List(0);
      
      final result = Uint8List(len);
      result.setAll(0, charPtr.cast<Uint8>().asTypedList(len));
      return result;
    } finally {
      calloc.free(pp);
    }
  }
}
