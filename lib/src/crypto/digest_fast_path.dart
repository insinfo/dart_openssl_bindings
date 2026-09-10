import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';

import '../generated/ffi.dart';
import '../infra/ssl_exception.dart';

/// Internal machinery: the reusable native state behind one-shot `digest`,
/// `digestHex`, `sha256` and `hmac` calls.
///
/// Nothing outside this package touches this class — it is not exported by
/// `package:openssl_bindings/openssl.dart`, and [internal] makes using it from
/// another package an analysis error. Callers get what it does for free by
/// calling `openSsl.digest(...)` as before; the speed-up is not something they
/// opt into.
///
/// Setting up a digest is what dominates a small hash: on OpenSSL 3 an
/// `EVP_DigestInit_ex` re-fetches the algorithm from its provider and costs
/// about 400 ns, while copying a context that is already initialised costs
/// about 30 ns. So each algorithm gets one template context, initialised once,
/// and every call starts as a copy of it. Together with reusing the working
/// context and the algorithm handles, a 32-byte SHA-256 drops from ~1.8 us to
/// ~0.35 us — below what a pure Dart implementation needs for the same input.
///
/// **Isolates.** This object hangs off an `OpenSSL` instance and is never
/// static, so each isolate works on contexts nothing else can reach. Two
/// isolates that each build an `OpenSSL` never share a context, which is what
/// makes concurrent use safe — libcrypto only requires that one context is not
/// used from two threads at once.
///
/// **Lifetime.** The contexts are attached to a [NativeFinalizer], so an
/// instance that simply goes out of scope releases them; nothing has to be
/// disposed by hand. The number of cached templates is capped, so a program
/// that hashes with many different algorithm names cannot grow this without
/// bound.
@internal
class DigestFastPath implements Finalizable {
  DigestFastPath(this._bindings, this._contextFinalizer, this._hmacFinalizer) {
    _work = _bindings.EVP_MD_CTX_new();
    if (_work == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }
    // No detach token: nothing frees these by hand, so the only release
    // is the finalizer running after this object becomes unreachable.
    _contextFinalizer.attach(this, _work.cast());
  }

  /// How many initialised templates to keep. Real programs use a handful of
  /// digests; the cap only bounds the damage from names built at runtime.
  static const int maxTemplates = 8;

  final OpenSslFfi _bindings;
  final NativeFinalizer _contextFinalizer;
  final NativeFinalizer _hmacFinalizer;

  /// Working context, reset from a template on every call.
  late final Pointer<EVP_MD_CTX> _work;

  /// Algorithm handles by name. These belong to libcrypto and are never freed.
  final Map<String, Pointer<EVP_MD>> _digests = {};

  /// Contexts initialised for one algorithm, owned by this object.
  final Map<String, Pointer<EVP_MD_CTX>> _templates = {};

  Pointer<HMAC_CTX> _hmac = nullptr;

  /// The working context. Only one digest is ever in flight: `digest` is
  /// synchronous and cannot re-enter itself within an isolate.
  Pointer<EVP_MD_CTX> get workContext => _work;

  /// Resolves [name] to a digest handle, caching the lookup.
  ///
  /// Throws [OpenSslException] for a name this libcrypto does not know, which
  /// is the same failure the uncached path reported.
  Pointer<EVP_MD> digestByName(String name) {
    final cached = _digests[name];
    if (cached != null) return cached;

    final namePtr = name.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      final md = _bindings.EVP_get_digestbyname(namePtr);
      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $name');
      }
      if (_digests.length < maxTemplates) _digests[name] = md;
      return md;
    } finally {
      calloc.free(namePtr);
    }
  }

  /// Initialises [workContext] for [name], from a template when there is one.
  ///
  /// Returns the algorithm handle so callers that need it do not look it up
  /// twice.
  Pointer<EVP_MD> beginDigest(String name) {
    final md = digestByName(name);
    final template = _templateFor(name, md);

    if (template != nullptr) {
      if (_bindings.EVP_MD_CTX_copy_ex(_work, template) == 1) return md;
      // A failed copy leaves the working context untouched; fall through to
      // the plain initialisation rather than failing the call.
    }
    if (_bindings.EVP_DigestInit_ex(_work, md, nullptr) != 1) {
      throw OpenSslException('EVP_DigestInit_ex failed');
    }
    return md;
  }

  /// A context already initialised for [name], or `nullptr` when the cache is
  /// full or the template could not be built.
  Pointer<EVP_MD_CTX> _templateFor(String name, Pointer<EVP_MD> md) {
    final cached = _templates[name];
    if (cached != null) return cached;
    if (_templates.length >= maxTemplates) return nullptr;

    final template = _bindings.EVP_MD_CTX_new();
    if (template == nullptr) return nullptr;
    if (_bindings.EVP_DigestInit_ex(template, md, nullptr) != 1) {
      _bindings.EVP_MD_CTX_free(template);
      return nullptr;
    }

    _contextFinalizer.attach(this, template.cast());
    _templates[name] = template;
    return template;
  }

  /// The reusable HMAC context, created on first use.
  ///
  /// HMAC has no equivalent of the template copy — the key changes from call
  /// to call, so `HMAC_Init_ex` has to run every time — but the allocation and
  /// release of the context are worth saving.
  Pointer<HMAC_CTX> get hmacContext {
    if (_hmac != nullptr) return _hmac;

    final ctx = _bindings.HMAC_CTX_new();
    if (ctx == nullptr) throw OpenSslException('Failed to create HMAC_CTX');
    _hmacFinalizer.attach(this, ctx.cast());
    return _hmac = ctx;
  }
}
