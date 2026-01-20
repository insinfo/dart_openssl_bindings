import '../generated/ffi.dart' as ffi;
import '../openssl_loader.dart';

/// Define o contrato básico para o contexto OpenSSL.
/// Classes que usam os mixins devem implementar esta interface.
abstract class OpenSslContext {
  /// Acesso aos bindings brutos gerados.
  ffi.OpenSsl get bindings;
  
  /// Acesso ao loader/configuração (opcional, se precisarmos de caminhos).
  OpenSslBindings get loader;
}
