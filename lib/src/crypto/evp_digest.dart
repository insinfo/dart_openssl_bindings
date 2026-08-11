import 'dart:ffi';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl_context.dart';
import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';
import '../utils/hex.dart';

/// `EVP_MAX_MD_SIZE`: the largest digest OpenSSL can produce, in bytes.
///
/// Hard-coded because it is a C macro, and macros are not part of the
/// generated bindings. It has been 64 since OpenSSL 1.0 (SHA-512/SHA3-512).
const int _maxDigestSize = 64;

/// An incremental (streaming) message digest.
///
/// Wraps an `EVP_MD_CTX` so a digest can be computed over input that arrives in
/// pieces — a file read chunk by chunk, a socket, an HTTP body — without ever
/// holding the whole input in memory. Native memory stays bounded by
/// [bufferSize] no matter how large the input or the individual chunks are.
/// For data already in memory, `OpenSSL.digest` is simpler.
///
/// Create it with `OpenSSL.startDigest`, feed it with [add] or [addStream], and
/// read the result with [finish]. [finish] releases the native context on
/// success; [dispose] releases it on any other path, so call it from a
/// `finally` — it is idempotent and safe to call after [finish]. A digest that
/// is garbage collected without either call is still released, by finalizer,
/// but that is a safety net rather than something to rely on.
///
/// ```dart
/// final digest = openSsl.startDigest('sha256');
/// try {
///   await digest.addStream(File('report.pdf').openRead());
///   print('${digest.length} bytes -> ${digest.finish()}');
/// } finally {
///   digest.dispose();
/// }
/// ```
///
/// An instance is not safe for concurrent use: it owns one scratch buffer and
/// one native context. Use one instance per computation. It is also bound to
/// the isolate that created it — like the [OpenSslContext] it came from, its
/// native pointers cannot be sent anywhere else.
class EvpDigest implements Finalizable {
  /// Starts a digest with [algorithmName], as named by OpenSSL — `sha256`,
  /// `sha512`, `sha3-256`, `sha1`, …
  ///
  /// [bufferSize] is the size of the scratch buffer used to hand chunks to
  /// OpenSSL, and therefore the ceiling on native memory held by this object.
  /// The default suits file and socket streams; there is no gain in making it
  /// larger than the chunks actually being fed.
  ///
  /// Throws [OpenSslException] if the loaded OpenSSL does not know
  /// [algorithmName] — including when it lives in a provider that has not been
  /// loaded, such as the `legacy` provider for older algorithms.
  EvpDigest(
    OpenSslContext context,
    this.algorithmName, {
    this.bufferSize = defaultBufferSize,
  }) : _bindings = context.bindings {
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'must be positive');
    }

    final arena = Arena();
    final Pointer<EVP_MD> md;
    try {
      final namePtr = algorithmName.toNativeUtf8(allocator: arena);
      md = _bindings.EVP_get_digestbyname(namePtr.cast());
    } finally {
      arena.releaseAll();
    }
    if (md == nullptr) {
      throw OpenSslException('Unknown digest algorithm: $algorithmName');
    }

    final ctx = _bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }
    if (_bindings.EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
      _bindings.EVP_MD_CTX_free(ctx);
      throw OpenSslException('EVP_DigestInit_ex failed for $algorithmName');
    }
    _ctx = ctx;
    _buffer = malloc<Uint8>(bufferSize);

    // Safety net for a digest abandoned without [finish] or [dispose]: the
    // context and the buffer are freed when this object is collected. Both
    // attachments are detached in [_release] so nothing is freed twice.
    _ctxFinalizer = NativeFinalizer(
      context
          .lookup<Void Function(Pointer<EVP_MD_CTX>)>('EVP_MD_CTX_free')
          .cast(),
    );
    _ctxFinalizer.attach(this, ctx.cast(), detach: this);
    _bufferFinalizer.attach(this, _buffer.cast(), detach: this);
  }

  /// Default scratch buffer size: 64 KiB, the chunk size `File.openRead` uses.
  static const int defaultBufferSize = 64 * 1024;

  static final NativeFinalizer _bufferFinalizer =
      NativeFinalizer(malloc.nativeFree);

  /// The digest algorithm being computed, as given to the constructor.
  final String algorithmName;

  /// Size of the scratch buffer handed to OpenSSL, in bytes.
  final int bufferSize;

  final OpenSslFfi _bindings;
  late final Pointer<EVP_MD_CTX> _ctx;
  late final Pointer<Uint8> _buffer;
  late final NativeFinalizer _ctxFinalizer;

  int _length = 0;
  bool _finished = false;
  bool _disposed = false;

  /// Number of bytes fed so far.
  ///
  /// Stays valid after [finish], which is what makes it usable for callers that
  /// need the size of what they hashed — an upload manifest, for instance —
  /// without walking the input twice.
  int get length => _length;

  /// Whether [finish] has already produced the digest.
  bool get isFinished => _finished;

  /// Whether the native resources have been released.
  bool get isDisposed => _disposed;

  /// Feeds [data] into the digest.
  ///
  /// Copies through the scratch buffer in [bufferSize] slices, so a chunk
  /// larger than the buffer is fine and costs no extra native memory.
  void add(List<int> data) {
    _ensureUsable();
    var offset = 0;
    while (offset < data.length) {
      final count = math.min(bufferSize, data.length - offset);
      _buffer.asTypedList(count).setRange(0, count, data, offset);
      if (_bindings.EVP_DigestUpdate(_ctx, _buffer.cast(), count) != 1) {
        throw OpenSslException('EVP_DigestUpdate failed');
      }
      offset += count;
      _length += count;
    }
  }

  /// Feeds everything [data] emits, in order, and completes when it closes.
  ///
  /// A failure in [data] — or in OpenSSL — propagates and leaves this digest
  /// unfinished; the caller's `finally` is still responsible for [dispose].
  Future<void> addStream(Stream<List<int>> data) async {
    await for (final chunk in data) {
      add(chunk);
    }
  }

  /// Produces the digest and releases the native context.
  ///
  /// The result is [length] bytes of input reduced to the algorithm's output
  /// size — 32 bytes for `sha256`. Calling it twice throws [StateError]: an
  /// `EVP_MD_CTX` cannot be finalized more than once.
  Uint8List finish() {
    _ensureUsable();

    final out = malloc<UnsignedChar>(_maxDigestSize);
    final outLen = malloc<UnsignedInt>();
    try {
      if (_bindings.EVP_DigestFinal_ex(_ctx, out, outLen) != 1) {
        throw OpenSslException('EVP_DigestFinal_ex failed');
      }
      final digest =
          Uint8List.fromList(out.cast<Uint8>().asTypedList(outLen.value));
      _finished = true;
      _release();
      return digest;
    } finally {
      malloc.free(out);
      malloc.free(outLen);
    }
  }

  /// Produces the digest as lowercase hexadecimal, and releases the context.
  ///
  /// Same as [finish], in the representation `package:crypto`'s
  /// `Digest.toString()` produces, which is what most systems store and
  /// compare.
  String finishHex() => encodeHex(finish());

  /// Releases the native context and scratch buffer.
  ///
  /// Idempotent, and already done by a successful [finish]. Call it from a
  /// `finally` so an input stream that fails halfway does not leak.
  void dispose() => _release();

  void _release() {
    if (_disposed) return;
    _disposed = true;
    _ctxFinalizer.detach(this);
    _bufferFinalizer.detach(this);
    _bindings.EVP_MD_CTX_free(_ctx);
    malloc.free(_buffer);
  }

  void _ensureUsable() {
    if (_finished) {
      throw StateError('This EvpDigest has already been finished.');
    }
    if (_disposed) {
      throw StateError('This EvpDigest has been disposed.');
    }
  }
}
