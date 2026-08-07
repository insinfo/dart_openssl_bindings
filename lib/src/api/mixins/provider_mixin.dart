import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';

/// Name of the OpenSSL 3.x default provider.
const String kDefaultProvider = 'default';

/// Name of the OpenSSL 3.x legacy provider.
///
/// It holds the algorithms that left the default provider in 3.0 — RC2, RC4,
/// DES, MD2/MD4 among them, and the `pbeWithSHA1And40BitRC2-CBC` used by old
/// PKCS#12 files.
const String kLegacyProvider = 'legacy';

/// A provider loaded into the default OpenSSL library context.
class OpenSslProvider {
  /// Name used to load it (`legacy`, `default`, `fips`, ...).
  final String name;

  /// Native `OSSL_PROVIDER *` handle.
  final Pointer<OSSL_PROVIDER> handle;

  OpenSslProvider(this.name, this.handle);

  @override
  String toString() => 'OpenSslProvider($name)';
}

/// OpenSSL 3.x provider API (`openssl/provider.h`).
///
/// Since OpenSSL 3.0 the algorithms considered obsolete moved from the
/// `default` provider to `legacy`, which is **not** loaded automatically.
/// Without it, operations such as opening a `.p12` encrypted with
/// `pbeWithSHA1And40BitRC2-CBC` fail with a generic error
/// (`PKCS12_parse failed`) that misleadingly points at the password.
///
/// ```dart
/// final openssl = OpenSSL();
/// openssl.loadLegacyProvider();
/// final bundle = openssl.parsePkcs12(der, password: pass, legacy: true);
/// ```
mixin ProviderMixin on OpenSslContext {
  /// Providers loaded by this instance, keyed by name.
  ///
  /// Per instance (rather than static) because each [OpenSSL] may have loaded a
  /// different libcrypto, with its own default context.
  final Map<String, OpenSslProvider> _loaded = {};

  /// Providers loaded so far (unmodifiable).
  Map<String, OpenSslProvider> get loadedProviders => Map.unmodifiable(_loaded);

  /// Loads a provider into the library's default context.
  ///
  /// [name] is the provider name (`legacy`, `default`, `fips`, `base`).
  ///
  /// [retainFallbacks] preserves the implicit activation of the `default`
  /// provider. **Keep it `true`**: OpenSSL disables the fallback providers as
  /// soon as any provider is loaded explicitly, so loading only `legacy` with
  /// `false` would take AES, SHA-2, RSA and everything else down with it.
  ///
  /// Calling it twice with the same name does not reload: it returns the
  /// provider already loaded.
  ///
  /// If the module is not found in the `MODULESDIR` compiled into libcrypto
  /// (common with the Windows installer, which points at a directory that does
  /// not exist), the search is retried in [searchPaths] and in the usual
  /// platform locations, unless [searchModule] is `false`.
  ///
  /// Throws [OpenSslException] when the provider cannot be loaded, unless
  /// [required] is `false` (in which case it returns `null`).
  OpenSslProvider? loadProvider(
    String name, {
    bool retainFallbacks = true,
    bool required = true,
    List<String> searchPaths = const [],
    bool searchModule = true,
  }) {
    final existing = _loaded[name];
    if (existing != null) return existing;

    var handle = _tryLoad(name, retainFallbacks);

    if (handle == nullptr && searchModule) {
      final previousPath = providerSearchPath;
      for (final dir in _moduleCandidates(name, searchPaths)) {
        setProviderSearchPath(dir);
        handle = _tryLoad(name, retainFallbacks);
        if (handle != nullptr) break;
      }
      if (handle == nullptr && previousPath != null) {
        setProviderSearchPath(previousPath);
      }
    }

    if (handle == nullptr) {
      final code = bindings.ERR_get_error();
      OpenSslException.clearError(bindings);
      if (!required) return null;
      throw OpenSslException(
        'Failed to load the "$name" provider. Check that the '
        '${_moduleFileName(name)} module exists in the OpenSSL modules '
        'directory (MODULESDIR) and that the loaded libcrypto is 3.x. The '
        'directory can be given to setProviderSearchPath() or through the '
        'OPENSSL_MODULES environment variable.',
        code,
        retainFallbacks ? 'OSSL_PROVIDER_try_load' : 'OSSL_PROVIDER_load',
      );
    }

    final provider = OpenSslProvider(name, handle);
    _loaded[name] = provider;
    return provider;
  }

  /// Loads the [kLegacyProvider] keeping `default` active.
  ///
  /// Required for RC2/RC4/DES and for PKCS#12 files built with
  /// `pbeWithSHA1And40BitRC2-CBC`.
  OpenSslProvider? loadLegacyProvider({
    bool required = true,
    List<String> searchPaths = const [],
  }) =>
      loadProvider(
        kLegacyProvider,
        required: required,
        searchPaths: searchPaths,
      );

  /// Unloads a provider loaded by [loadProvider].
  ///
  /// Returns `false` when the provider was not loaded.
  bool unloadProvider(String name) {
    final provider = _loaded.remove(name);
    if (provider == null) return false;

    if (bindings.OSSL_PROVIDER_unload(provider.handle) != 1) {
      throw OpenSslException(
        'Failed to unload the "$name" provider',
        bindings.ERR_get_error(),
        'OSSL_PROVIDER_unload',
      );
    }
    return true;
  }

  /// Unloads every provider loaded through this instance.
  void unloadProviders() {
    for (final name in _loaded.keys.toList()) {
      unloadProvider(name);
    }
  }

  /// Whether the [name] provider is available for use.
  ///
  /// Unlike [loadProvider], it keeps no reference to the provider.
  bool isProviderAvailable(String name) {
    final namePtr = name.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      OpenSslException.clearError(bindings);
      final available = bindings.OSSL_PROVIDER_available(nullptr, namePtr) == 1;
      OpenSslException.clearError(bindings);
      return available;
    } finally {
      calloc.free(namePtr);
    }
  }

  /// Sets the directory where OpenSSL looks for provider modules
  /// (`legacy.dll`, `legacy.so`, ...).
  ///
  /// Useful when libcrypto was loaded from a custom path and the modules are
  /// not in the directory compiled into it.
  void setProviderSearchPath(String path) {
    final pathPtr = path.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      final result =
          bindings.OSSL_PROVIDER_set_default_search_path(nullptr, pathPtr);
      if (result != 1) {
        throw OpenSslException(
          'Failed to set the provider search path "$path"',
          bindings.ERR_get_error(),
          'OSSL_PROVIDER_set_default_search_path',
        );
      }
    } finally {
      calloc.free(pathPtr);
    }
  }

  /// Provider search directory in use, or `null` when it is the built-in one.
  ///
  /// Also `null` on libcrypto older than 3.2, which has no
  /// `OSSL_PROVIDER_get0_default_search_path` to ask — the Ubuntu LTS ships
  /// 3.0. Only reading it back is lost; [setProviderSearchPath] has been there
  /// since 3.0.
  String? get providerSearchPath {
    final Pointer<Char> ptr;
    try {
      ptr = bindings.OSSL_PROVIDER_get0_default_search_path(nullptr);
    } on ArgumentError {
      return null;
    }
    if (ptr == nullptr) return null;
    return ptr.cast<Utf8>().toDartString();
  }

  Pointer<OSSL_PROVIDER> _tryLoad(String name, bool retainFallbacks) {
    final namePtr = name.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      OpenSslException.clearError(bindings);
      return retainFallbacks
          ? bindings.OSSL_PROVIDER_try_load(nullptr, namePtr, 1)
          : bindings.OSSL_PROVIDER_load(nullptr, namePtr);
    } finally {
      calloc.free(namePtr);
    }
  }

  String _moduleFileName(String name) {
    if (Platform.isWindows) return '$name.dll';
    if (Platform.isMacOS) return '$name.dylib';
    return '$name.so';
  }

  /// Directories that may hold the module of the [name] provider, already
  /// filtered down to the ones that actually contain the file.
  Iterable<String> _moduleCandidates(String name, List<String> extra) sync* {
    final fileName = _moduleFileName(name);
    final seen = <String>{};

    for (final dir in [...extra, ..._moduleDirectories()]) {
      if (dir.isEmpty || !seen.add(dir)) continue;
      if (File('$dir${Platform.pathSeparator}$fileName').existsSync()) {
        yield dir;
      }
    }
  }

  List<String> _moduleDirectories() {
    final env = Platform.environment;
    final dirs = <String>[
      if (env['OPENSSL_MODULES'] != null) env['OPENSSL_MODULES']!,
      if (env['OPENSSL_LIB_DIR'] != null) ...[
        env['OPENSSL_LIB_DIR']!,
        '${env['OPENSSL_LIB_DIR']}${Platform.pathSeparator}ossl-modules',
      ],
    ];

    if (Platform.isWindows) {
      dirs.addAll(const [
        r'C:\Program Files\OpenSSL-Win64\bin',
        r'C:\Program Files\OpenSSL-Win64\lib\ossl-modules',
        r'C:\Program Files\OpenSSL\bin',
        r'C:\Program Files\OpenSSL\lib\ossl-modules',
        r'C:\msys64\mingw64\lib\ossl-modules',
        r'C:\msys64\usr\lib\ossl-modules',
      ]);
    } else if (Platform.isMacOS) {
      dirs.addAll(const [
        '/opt/homebrew/lib/ossl-modules',
        '/usr/local/lib/ossl-modules',
        '/usr/local/opt/openssl@3/lib/ossl-modules',
      ]);
    } else {
      dirs.addAll(const [
        '/usr/lib/x86_64-linux-gnu/ossl-modules',
        '/usr/lib/aarch64-linux-gnu/ossl-modules',
        '/usr/lib64/ossl-modules',
        '/usr/lib/ossl-modules',
        '/usr/local/lib/ossl-modules',
        '/usr/local/lib64/ossl-modules',
      ]);
    }

    return dirs;
  }
}
