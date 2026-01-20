import 'dart:ffi'; 
import '../openssl_loader.dart';
import '../generated/ffi.dart';
import 'openssl_context.dart';
import 'mixins/mixins.dart';

/// A classe principal que representa uma instância da biblioteca OpenSSL.
/// Agrega funcionalidade através de Mixins.
class OpenSSL extends OpenSslContext with BioMixin, CryptoMixin, SignatureMixin, X509Mixin {
  final OpenSslBindings _loader;
  
  /// Carrega a biblioteca OpenSSL.
  /// 
  /// [dynamicPath] permite especificar o caminho/nome da DLL/SO.
  OpenSSL({String? dynamicPath}) 
    : _loader = OpenSslBindings.load(cryptoPath: dynamicPath);

  @override
  OpenSsl get bindings => _loader.crypto; // ou .ssl dependendo de onde está o simbolo

  @override
  OpenSslBindings get loader => _loader;
  
  /// Helper para pegar endereços de funções (para NativeFinalizer).
  Pointer<NativeFunction<T>> lookup<T extends Function>(String name) {
    // Tenta no crypto e no ssl
    try {
      return _loader.cryptoLibrary.lookup<NativeFunction<T>>(name);
    } catch (_) {
      return _loader.sslLibrary.lookup<NativeFunction<T>>(name);
    }
  }
}
