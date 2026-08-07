import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl_context.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import 'argon2/argon2_pure.dart' as pure;

/// Argon2 variants (RFC 9106).
enum Argon2Type {
  /// Data-dependent addressing. Fastest, but weaker against side channels.
  d('ARGON2D', pure.Argon2Parameters.ARGON2_d),

  /// Data-independent addressing. Side-channel resistant, weaker against
  /// time-memory trade-off attacks.
  i('ARGON2I', pure.Argon2Parameters.ARGON2_i),

  /// Hybrid of [d] and [i]. **The one to use** for password hashing.
  id('ARGON2ID', pure.Argon2Parameters.ARGON2_id);

  const Argon2Type(this.opensslName, this.code);

  /// Algorithm name as OpenSSL's `EVP_KDF_fetch` expects it.
  final String opensslName;

  /// Numeric type as encoded in the PHC string (`$argon2id$`).
  final int code;

  /// Name used in the PHC string.
  String get phcName => 'argon2${name}';
}

/// Argon2 parameters. The defaults follow the RFC 9106 "second recommended"
/// profile: 64 MiB of memory, 3 passes, 1 lane.
class Argon2Options {
  /// Variant to use.
  final Argon2Type type;

  /// Number of passes over memory (`t`). More passes, more time.
  final int iterations;

  /// Memory cost in **kibibytes** (`m`). 65536 means 64 MiB.
  final int memoryKib;

  /// Degree of parallelism (`p`), also called lanes.
  ///
  /// Values above 1 are only honoured by the pure Dart implementation and by
  /// OpenSSL builds with a configured thread pool; see [Argon2.derive].
  final int lanes;

  /// Output length in bytes.
  final int length;

  /// Optional key ("pepper"), mixed into the hash. Not stored in the PHC
  /// string, so it has to be supplied again at verification time.
  final Uint8List? secret;

  /// Optional associated data.
  final Uint8List? associatedData;

  const Argon2Options({
    this.type = Argon2Type.id,
    this.iterations = 3,
    this.memoryKib = 65536,
    this.lanes = 1,
    this.length = 32,
    this.secret,
    this.associatedData,
  });

  /// Cheap profile for tests and interactive flows where 64 MiB is too much.
  static const Argon2Options interactive = Argon2Options(
    iterations: 2,
    memoryKib: 19456,
  );

  /// Copy with individual fields replaced.
  Argon2Options copyWith({
    Argon2Type? type,
    int? iterations,
    int? memoryKib,
    int? lanes,
    int? length,
    Uint8List? secret,
    Uint8List? associatedData,
  }) =>
      Argon2Options(
        type: type ?? this.type,
        iterations: iterations ?? this.iterations,
        memoryKib: memoryKib ?? this.memoryKib,
        lanes: lanes ?? this.lanes,
        length: length ?? this.length,
        secret: secret ?? this.secret,
        associatedData: associatedData ?? this.associatedData,
      );

  @override
  String toString() => 'Argon2Options(${type.phcName}, m=$memoryKib, '
      't=$iterations, p=$lanes, len=$length)';
}

/// Which implementation produced a hash.
enum Argon2Backend {
  /// OpenSSL's `EVP_KDF` Argon2 (3.2+).
  native,

  /// The pure Dart implementation vendored with this package.
  dart,
}

/// Argon2 password hashing and key derivation.
///
/// Uses OpenSSL's native Argon2 (`EVP_KDF`, available from OpenSSL 3.2) when
/// the loaded libcrypto provides it, and falls back to the pure Dart
/// implementation otherwise — the output is identical either way, it is the
/// same algorithm.
///
/// ```dart
/// final openssl = OpenSSL();
/// final phc = openssl.argon2HashPassword('secret');   // $argon2id$v=19$...
/// final ok = openssl.argon2VerifyPassword(phc, 'secret');
/// ```
mixin Argon2Mixin on OpenSslContext {
  bool? _nativeArgon2;

  /// Whether the loaded libcrypto offers native Argon2 (OpenSSL 3.2+).
  bool get hasNativeArgon2 {
    final cached = _nativeArgon2;
    if (cached != null) return cached;

    var available = false;
    try {
      final namePtr = 'ARGON2ID'.toNativeUtf8(allocator: calloc).cast<Char>();
      try {
        OpenSslException.clearError(bindings);
        final kdf = bindings.EVP_KDF_fetch(nullptr, namePtr, nullptr);
        available = kdf != nullptr;
        if (kdf != nullptr) bindings.EVP_KDF_free(kdf);
        OpenSslException.clearError(bindings);
      } finally {
        calloc.free(namePtr);
      }
    } on ArgumentError {
      // libcrypto without the EVP_KDF symbols at all (OpenSSL 1.x).
      available = false;
    }

    _nativeArgon2 = available;
    return available;
  }

  /// Derives [options].length bytes from [password] and [salt].
  ///
  /// [backend] forces an implementation; by default the native one is used
  /// when available. Note that OpenSSL rejects `lanes > 1` unless its library
  /// context has a thread pool configured, so with more lanes this falls back
  /// to the Dart implementation instead of failing.
  Uint8List argon2Derive(
    Uint8List password,
    Uint8List salt, {
    Argon2Options options = const Argon2Options(),
    Argon2Backend? backend,
  }) {
    _validate(options, salt);

    final useNative = backend == null
        ? hasNativeArgon2 && options.lanes == 1
        : backend == Argon2Backend.native;

    if (useNative) {
      return _deriveNative(password, salt, options);
    }
    return _deriveDart(password, salt, options);
  }

  /// Same as [argon2Derive], taking the password as a UTF-8 string.
  Uint8List argon2DeriveFromString(
    String password,
    Uint8List salt, {
    Argon2Options options = const Argon2Options(),
    Argon2Backend? backend,
  }) =>
      argon2Derive(
        Uint8List.fromList(utf8.encode(password)),
        salt,
        options: options,
        backend: backend,
      );

  /// Hashes [password] and encodes the result as a PHC string, the format
  /// `$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>` used by most password
  /// databases.
  ///
  /// [salt] defaults to 16 random bytes taken from OpenSSL's RNG.
  String argon2HashPassword(
    String password, {
    Argon2Options options = const Argon2Options(),
    Uint8List? salt,
    Argon2Backend? backend,
  }) {
    final effectiveSalt = salt ?? randomBytes(16);
    final hash = argon2DeriveFromString(
      password,
      effectiveSalt,
      options: options,
      backend: backend,
    );
    return encodeArgon2Phc(hash, effectiveSalt, options);
  }

  /// Checks [password] against a PHC string produced by [argon2HashPassword].
  ///
  /// Returns `false` for a malformed string instead of throwing, so a corrupt
  /// stored hash cannot be told apart from a wrong password by timing or by
  /// exception type. [secret] must be supplied again when the hash was created
  /// with one.
  bool argon2VerifyPassword(
    String phc,
    String password, {
    Uint8List? secret,
    Uint8List? associatedData,
    Argon2Backend? backend,
  }) {
    final parsed = tryParseArgon2Phc(phc);
    if (parsed == null) return false;

    final options = parsed.options.copyWith(
      secret: secret,
      associatedData: associatedData,
    );

    final computed = argon2DeriveFromString(
      password,
      parsed.salt,
      options: options,
      backend: backend,
    );

    return _constantTimeEquals(computed, parsed.hash);
  }

  /// Random bytes from OpenSSL's RNG.
  Uint8List randomBytes(int length) {
    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }
    final buffer = calloc<UnsignedChar>(length);
    try {
      if (bindings.RAND_bytes(buffer, length) != 1) {
        throw OpenSslException('RAND_bytes failed');
      }
      return Uint8List.fromList(buffer.cast<Uint8>().asTypedList(length));
    } finally {
      calloc.free(buffer);
    }
  }

  // ---------------------------------------------------------------------------
  // Backends
  // ---------------------------------------------------------------------------

  Uint8List _deriveNative(
    Uint8List password,
    Uint8List salt,
    Argon2Options options,
  ) {
    final arena = Arena();
    Pointer<EVP_KDF> kdf = nullptr;
    Pointer<EVP_KDF_CTX> ctx = nullptr;

    try {
      final namePtr =
          options.type.opensslName.toNativeUtf8(allocator: arena).cast<Char>();
      kdf = bindings.EVP_KDF_fetch(nullptr, namePtr, nullptr);
      if (kdf == nullptr) {
        throw OpenSslException(
          'Native Argon2 is not available in this libcrypto (needs OpenSSL '
          '3.2+); pass backend: Argon2Backend.dart to use the Dart one',
          bindings.ERR_get_error(),
          'EVP_KDF_fetch',
        );
      }

      ctx = bindings.EVP_KDF_CTX_new(kdf);
      if (ctx == nullptr) {
        throw OpenSslException('EVP_KDF_CTX_new failed');
      }

      final params = <OSSL_PARAM>[
        _octetParam(arena, 'pass', password),
        _octetParam(arena, 'salt', salt),
        _uintParam(arena, 'iter', options.iterations),
        _uintParam(arena, 'memcost', options.memoryKib),
        _uintParam(arena, 'lanes', options.lanes),
        _uintParam(arena, 'threads', options.lanes),
        if (options.secret != null) _octetParam(arena, 'secret', options.secret!),
        if (options.associatedData != null)
          _octetParam(arena, 'ad', options.associatedData!),
      ];

      final paramArray = arena<OSSL_PARAM>(params.length + 1);
      for (var i = 0; i < params.length; i++) {
        paramArray[i] = params[i];
      }
      paramArray[params.length] = bindings.OSSL_PARAM_construct_end();

      OpenSslException.clearError(bindings);
      final out = arena<UnsignedChar>(options.length);
      final result = bindings.EVP_KDF_derive(
        ctx,
        out,
        options.length,
        paramArray,
      );
      if (result != 1) {
        throw OpenSslException(
          'EVP_KDF_derive failed for ${options.type.opensslName}',
          bindings.ERR_get_error(),
          'EVP_KDF_derive',
        );
      }

      return Uint8List.fromList(
        out.cast<Uint8>().asTypedList(options.length),
      );
    } finally {
      if (ctx != nullptr) bindings.EVP_KDF_CTX_free(ctx);
      if (kdf != nullptr) bindings.EVP_KDF_free(kdf);
      arena.releaseAll();
    }
  }

  Uint8List _deriveDart(
    Uint8List password,
    Uint8List salt,
    Argon2Options options,
  ) {
    final parameters = pure.Argon2Parameters(
      options.type.code,
      salt,
      secret: options.secret,
      additional: options.associatedData,
      iterations: options.iterations,
      memory: options.memoryKib,
      lanes: options.lanes,
      version: pure.Argon2Parameters.ARGON2_VERSION_13,
    );

    final generator = pure.Argon2BytesGenerator()..init(parameters);
    final out = Uint8List(options.length);
    generator.generateBytes(password, out, 0, options.length);
    return out;
  }

  OSSL_PARAM _octetParam(Arena arena, String key, Uint8List value) {
    final keyPtr = key.toNativeUtf8(allocator: arena);
    final data = arena<UnsignedChar>(value.isEmpty ? 1 : value.length);
    if (value.isNotEmpty) {
      data.cast<Uint8>().asTypedList(value.length).setAll(0, value);
    }
    return bindings.OSSL_PARAM_construct_octet_string(
      keyPtr.cast(),
      data.cast(),
      value.length,
    );
  }

  OSSL_PARAM _uintParam(Arena arena, String key, int value) {
    final keyPtr = key.toNativeUtf8(allocator: arena);
    final holder = arena<Uint32>()..value = value;
    return bindings.OSSL_PARAM_construct_uint32(keyPtr.cast(), holder);
  }

  void _validate(Argon2Options options, Uint8List salt) {
    if (salt.length < 8) {
      throw ArgumentError.value(
        salt.length,
        'salt.length',
        'Argon2 requires a salt of at least 8 bytes',
      );
    }
    if (options.length < 4) {
      throw ArgumentError.value(
        options.length,
        'options.length',
        'Argon2 output must be at least 4 bytes',
      );
    }
    if (options.iterations < 1) {
      throw ArgumentError.value(
        options.iterations,
        'options.iterations',
        'must be at least 1',
      );
    }
    if (options.lanes < 1) {
      throw ArgumentError.value(options.lanes, 'options.lanes', 'must be >= 1');
    }
    if (options.memoryKib < 8 * options.lanes) {
      throw ArgumentError.value(
        options.memoryKib,
        'options.memoryKib',
        'must be at least 8 * lanes',
      );
    }
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}

/// A parsed PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
class Argon2Phc {
  /// Parameters encoded in the string.
  final Argon2Options options;

  /// Salt, already base64-decoded.
  final Uint8List salt;

  /// Hash, already base64-decoded.
  final Uint8List hash;

  const Argon2Phc({
    required this.options,
    required this.salt,
    required this.hash,
  });
}

/// Encodes [hash] and [salt] in the PHC string format.
String encodeArgon2Phc(Uint8List hash, Uint8List salt, Argon2Options options) {
  final saltB64 = _b64NoPad(salt);
  final hashB64 = _b64NoPad(hash);
  return '\$${options.type.phcName}\$v=19'
      '\$m=${options.memoryKib},t=${options.iterations},p=${options.lanes}'
      '\$$saltB64\$$hashB64';
}

/// Parses a PHC string, or returns `null` when it is malformed or uses
/// something this package does not support.
Argon2Phc? tryParseArgon2Phc(String phc) {
  final parts = phc.split('\$');
  // ['', 'argon2id', 'v=19', 'm=..,t=..,p=..', salt, hash]
  if (parts.length != 6 || parts[0].isNotEmpty) return null;

  final type = switch (parts[1]) {
    'argon2id' => Argon2Type.id,
    'argon2i' => Argon2Type.i,
    'argon2d' => Argon2Type.d,
    _ => null,
  };
  if (type == null) return null;

  if (parts[2] != 'v=19') return null;

  int? memory;
  int? iterations;
  int? lanes;
  for (final field in parts[3].split(',')) {
    final kv = field.split('=');
    if (kv.length != 2) return null;
    final value = int.tryParse(kv[1]);
    if (value == null) return null;
    switch (kv[0]) {
      case 'm':
        memory = value;
      case 't':
        iterations = value;
      case 'p':
        lanes = value;
      default:
        return null;
    }
  }
  if (memory == null || iterations == null || lanes == null) return null;

  final Uint8List salt;
  final Uint8List hash;
  try {
    salt = _b64Decode(parts[4]);
    hash = _b64Decode(parts[5]);
  } on FormatException {
    return null;
  }
  if (salt.isEmpty || hash.length < 4) return null;

  return Argon2Phc(
    options: Argon2Options(
      type: type,
      iterations: iterations,
      memoryKib: memory,
      lanes: lanes,
      length: hash.length,
    ),
    salt: salt,
    hash: hash,
  );
}

String _b64NoPad(Uint8List data) =>
    base64.encode(data).replaceAll('=', '');

Uint8List _b64Decode(String value) {
  final padding = (4 - value.length % 4) % 4;
  return Uint8List.fromList(base64.decode(value + ('=' * padding)));
}
