import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../openssl_context.dart';

// Constante necessária (deveria estar no ffi.dart ou bio_helper)
const int BIO_CTRL_INFO = 3;

/// Mixin responsável por operações de BIO (Memory Buffer).
mixin BioMixin on OpenSslContext {
  
  /// Cria um BIO a partir de uma String.
  Pointer<BIO> createBioFromString(String text) {
    // É mais seguro alocar memória Dart e copiar, ou usar BIO_new_mem_buf.
    // BIO_new_mem_buf cria um BIO read-only se passarmos ponteiro direto.
    // Para simplificar e garantir ownership, vamos criar um BIO de memória e escrever nele.
    
    final bio = bindings.BIO_new(bindings.BIO_s_mem());
    if (bio == nullptr) throw OpenSslException('Failed to create BIO');
    
    final units = text.codeUnits;
    final buffer = calloc<Uint8>(units.length);
    try {
      buffer.asTypedList(units.length).setAll(0, units);
      final written = bindings.BIO_write(bio, buffer.cast(), units.length);
      if (written <= 0) throw OpenSslException('Failed to write to BIO');
    } finally {
      calloc.free(buffer);
    }
    return bio;
  }

  /// Cria um BIO vazio (Writable).
  Pointer<BIO> createBio() {
     final bio = bindings.BIO_new(bindings.BIO_s_mem());
     if (bio == nullptr) throw OpenSslException('Failed to create BIO');
     return bio;
  }

  /// Lê todo o conteúdo de um BIO para String.
  String bioToString(Pointer<BIO> bio) {
    final pp = calloc<Pointer<Char>>();
    try {
      final len = bindings.BIO_ctrl(bio, BIO_CTRL_INFO, 0, pp.cast());
      if (len < 0) throw OpenSslException('BIO_ctrl failed to get data');
      
      final charPtr = pp.value;
      if (charPtr == nullptr || len == 0) return '';
      
      final result = charPtr.cast<Uint8>().asTypedList(len);
      return String.fromCharCodes(result); 
    } finally {
      calloc.free(pp);
    }
  }

  /// Libera um BIO.
  void freeBio(Pointer<BIO> bio) {
    if (bio != nullptr) {
      bindings.BIO_free(bio);
    }
  }
}
