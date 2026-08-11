import 'dart:ffi';
import '../openssl_loader.dart';
import '../generated/ffi.dart';
import 'openssl_context.dart';
import 'mixins/mixins.dart';
import '../kdf/argon2.dart';
import '../ts/timestamp.dart';

/// The main entry point: one loaded instance of the OpenSSL library.
///
/// Functionality is aggregated through mixins — digests and keys
/// ([CryptoMixin]), ciphers, X.509, CMS, OCSP, PKCS, time-stamping and the
/// rest — so everything hangs off a single object:
///
/// ```dart
/// final openSsl = OpenSSL();
/// final hash = openSsl.digestHex('sha256', bytes);
/// ```
///
/// ## One instance per isolate
///
/// **An `OpenSSL` instance cannot cross an isolate boundary, and neither can
/// anything holding a handle from it** — `EvpPkey`, `X509Certificate`,
/// `EvpDigest`, and so on. The instance owns a `DynamicLibrary` and raw
/// pointers, which are not sendable and are only valid in the isolate that
/// created them. Sending one fails at runtime with:
///
/// ```text
/// Invalid argument(s): Illegal argument in isolate message:
///   (object is a DynamicLibrary)
/// ```
///
/// So every isolate that needs OpenSSL builds its own instance. Within an
/// isolate, one instance is safe to share across concurrent operations: each
/// call allocates its own context and frees it before returning, and the
/// instance itself only holds the loaded library's function pointers. Keeping
/// one per isolate — rather than one per call — is the right shape:
///
/// ```dart
/// // In a long-lived worker isolate:
/// final openSsl = OpenSSL();          // once, for the isolate's lifetime
/// await for (final job in inbox) { … } // shared by every job
/// ```
///
/// The trap is doing it by accident. A closure passed to `Isolate.run` carries
/// its entire captured context, including parent scopes it never reads, so
/// writing the closure anywhere an `OpenSSL` variable is in scope drags the
/// instance along and the spawn fails. Hoist the work into a top-level function
/// whose scope holds only sendable data:
///
/// ```dart
/// // Wrong: captures `openSsl` from the enclosing scope, even unused.
/// final openSsl = OpenSSL();
/// await Isolate.run(() => OpenSSL().digestHex('sha256', data)); // throws
///
/// // Right: a top-level function, nothing but sendable data in scope.
/// Future<String> hashInIsolate(Uint8List data) =>
///     Isolate.run(() => OpenSSL().digestHex('sha256', data));
/// ```
///
/// ## Cost of loading
///
/// Building an instance loads libcrypto/libssl, so a short-lived isolate pays
/// that on every spawn. For small inputs — a few kilobytes — that load can cost
/// more than the hashing it enables, and a pure-Dart implementation may well
/// win. The native advantage shows up on large inputs and on long-lived
/// isolates that amortise the load. Measure before moving small, hot,
/// per-spawn work onto OpenSSL.
///
/// See `test/concurrency/multi_isolate_stress_test.dart`, which pins all of the
/// above against a multi-isolate workload.
class OpenSSL extends OpenSslContext
  with BioMixin, CryptoMixin, Asn1Mixin, CmsMixin, SignatureMixin, X509Mixin, CipherMixin, PkcsMixin, OcspMixin, PkiMixin, PkiBuilderMixin, ProviderMixin, VerificationMixin, Argon2Mixin, TimestampMixin {
  final OpenSslBindings _loader;

  /// Carrega a biblioteca OpenSSL.
  ///
  /// [dynamicPath] permite especificar o caminho/nome da DLL/SO.
  OpenSSL(
   { String? cryptoPath,
    String? sslPath,}
  ) : _loader = OpenSslBindings.load(cryptoPath: cryptoPath, sslPath: sslPath);

  @override
  OpenSslFfi get bindings =>
      _loader.crypto; // ou .ssl dependendo de onde está o simbolo

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

  /// OpenSSL version (major).
  int get opensslVersionMajor => bindings.OPENSSL_version_major();

  /// OpenSSL version (minor).
  int get opensslVersionMinor => bindings.OPENSSL_version_minor();

  /// OpenSSL version (patch).
  int get opensslVersionPatch => bindings.OPENSSL_version_patch();

  /// OpenSSL version string (major.minor.patch).
  String get opensslVersionString =>
      '${opensslVersionMajor}.${opensslVersionMinor}.${opensslVersionPatch}';
}
