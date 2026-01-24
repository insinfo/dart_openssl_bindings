import 'dart:ffi';
import 'dart:io';
import '../generated/ffi.dart';

/// Singleton that manages loading the OpenSSL Dynamic Library.
class OpenSslLib {
  static OpenSslFfi? _instance;
  static DynamicLibrary? _dylib;

  /// Access the generated OpenSSL bindings.
  static OpenSslFfi get instance {
    if (_instance == null) {
      _load();
    }
    return _instance!;
  }

  /// Explicitly initializes the library with a specific path if needed.
  static void init(String path) {
    _dylib = DynamicLibrary.open(path);
    _instance = OpenSslFfi(_dylib!);
    _initCrypto();
  }

  static void _load() {
    if (_instance != null) return;

    try {
      if (Platform.isWindows) {
        _tryLoad(['libcrypto-3-x64.dll', 'libcrypto-1_1-x64.dll', 'libcrypto.dll']);
      } else if (Platform.isLinux) {
        _tryLoad(['libcrypto.so.3', 'libcrypto.so']);
      } else if (Platform.isMacOS) {
        _tryLoad(['libcrypto.3.dylib', 'libcrypto.dylib']);
      } else {
        throw UnsupportedError('Platform not supported for automatic loading');
      }
    } catch (e) {
      throw FileSystemException('Failed to load OpenSSL library: $e');
    }
    
    _initCrypto();
  }

  static void _tryLoad(List<String> names) {
    for (final name in names) {
      try {
        _dylib = DynamicLibrary.open(name);
        _instance = OpenSslFfi(_dylib!);
        return;
      } catch (e) {
        // Try next
      }
    }
    throw Exception('Could not find OpenSSL library in paths: $names');
  }

  static void _initCrypto() {
    // OpenSSL 1.1+ handles init automatically, but if we need explicit init seeds
    // or loading config, it would go here.
    // instance.OPENSSL_init_crypto(0, nullptr);
  }
  
  /// Helper to lookup a symbol for NativeFinalizer
  static Pointer<NativeFunction<T>> lookup<T extends Function>(String symbolName) {
    if (_dylib == null) _load();
    return _dylib!.lookup<NativeFunction<T>>(symbolName);
  }
}
