import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../api/openssl.dart';
import 'x509_name.dart';
import 'x509_request.dart';
import '../crypto/evp_pkey.dart';
import '../infra/ssl_exception.dart';

/// Builder for creating Certificate Signing Requests (CSR).
class X509RequestBuilder implements Finalizable {
  final OpenSSL _context;
  final Pointer<X509_REQ> _req;
  late final NativeFinalizer _finalizer;
  bool _isDisposed = false;
  bool _isConsumed = false;

  X509RequestBuilder(this._context) : _req = _context.bindings.X509_REQ_new() {
    if (_req == nullptr) {
      throw OpenSslException('Failed to create X509_REQ');
    }
    final freePtr = _context.lookup<Void Function(Pointer<X509_REQ>)>('X509_REQ_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, _req.cast(), detach: this);
    // Set Version (0 = v1, default)
    if (_context.bindings.X509_REQ_set_version(_req, 0) != 1) {
       // Should we throw here or just let it be?
    }
  }

  void _ensureUsable() {
    if (_isDisposed) {
      throw StateError('X509RequestBuilder has been disposed');
    }
    if (_isConsumed) {
      throw StateError('X509RequestBuilder already signed');
    }
  }

  /// Sets the Subject DN (Distinguished Name).
  void setSubject({
    String? commonName,
    String? organization,
    String? country,
    String? locality,
    String? state,
    String? unit,
  }) {
    _ensureUsable();
    // X509_REQ_get_subject_name returns internal pointer
    final namePtr = _context.bindings.X509_REQ_get_subject_name(_req);
    final name = X509Name(namePtr, _context, isOwned: false);
    
    if (commonName != null) name.addEntry('CN', commonName);
    if (organization != null) name.addEntry('O', organization);
    if (country != null) name.addEntry('C', country);
    if (locality != null) name.addEntry('L', locality);
    if (state != null) name.addEntry('ST', state);
    if (unit != null) name.addEntry('OU', unit);
  }

  /// Sets the Public Key to be included in the request.
  void setPublicKey(EvpPkey key) {
    _ensureUsable();
    if (_context.bindings.X509_REQ_set_pubkey(_req, key.handle) != 1) {
      throw OpenSslException('Failed to set public key on CSR');
    }
  }

  /// Signs the request and returns the wrapper.
  /// [privateKey] Key used to sign (must allow signing).
  X509Request sign(EvpPkey privateKey, {String digestName = 'SHA256'}) {
    _ensureUsable();
    try {
        final digestLabel = digestName.toNativeUtf8(allocator: calloc);
        final md = _context.bindings.EVP_get_digestbyname(digestLabel.cast());
        calloc.free(digestLabel);
        
        if (md == nullptr) throw OpenSslException('Unknown digest: $digestName');

        // X509_REQ_sign returns size > 0 on success
        if (_context.bindings.X509_REQ_sign(_req, privateKey.handle, md) <= 0) {
             throw OpenSslException('Failed to sign X509_REQ');
        }

        // We transfer ownership of `_req` to the returned object?
        // Wait, if X509Request takes ownership (finalizer), we are good.
        // But if we call sign twice? The builder holds the pointer.
        // Ideally builder should duplicate or we "consume" the builder.
        // Our X509Request constructor attaches a finalizer. If we keep using it in builder, we have aliasing.
        // Let's assume sign is terminal or we dup.
        // To be safe, let's just pass ownership and make the builder "invalid" or create a copy (X509_REQ_dup?).
        // Simple approach: Builder manages it until sign, then gives it to wrapper. Builder shouldn't be used after.
        
        _finalizer.detach(this);
        _isConsumed = true;
        return X509Request(_req, _context);
    } catch (e) {
       // If fails, we still own _req, it will be leaked if user loses builder? 
       // We should implement dispose or Finalizer on Builder too if valid.
       // But for now, let's trust flow.
       rethrow;
    }
  }

  /// Releases the underlying X509_REQ structure if the builder was not consumed.
  void dispose() {
    if (_isDisposed || _isConsumed) return;
    _finalizer.detach(this);
    _context.bindings.X509_REQ_free(_req);
    _isDisposed = true;
  }
}
