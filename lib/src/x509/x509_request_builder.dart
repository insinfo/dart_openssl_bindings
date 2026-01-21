import 'dart:ffi';
import 'package:ffi/ffi.dart';
import '../api/openssl.dart';
import 'x509_name.dart';
import 'x509_request.dart';
import '../crypto/evp_pkey.dart';
import '../infra/ssl_exception.dart';

/// Builder for creating Certificate Signing Requests (CSR).
class X509RequestBuilder {
  final OpenSSL _context;

  X509RequestBuilder(this._context);

  /// Creates a Certificate Signing Request (CSR).
  /// 
  /// [subject] The subject name for the certificate.
  /// [keyPair] The key pair (private/public) to sign the request and set as public key.
  /// [digestName] The digest algorithm to use for signing (default: "SHA256").
  X509Request build({
    required X509Name subject,
    required EvpPkey keyPair, 
    String digestName = 'SHA256',
  }) {
    final req = _context.bindings.X509_REQ_new();
    if (req == nullptr) {
        throw OpenSslException('Failed to create X509_REQ');
    }

    try {
        // Set Version (0 = v1)
        if (_context.bindings.X509_REQ_set_version(req, 0) != 1) {
            throw OpenSslException('Failed to set X509_REQ version');
        }

        // Set Subject
        if (_context.bindings.X509_REQ_set_subject_name(req, subject.handle) != 1) {
            throw OpenSslException('Failed to set X509_REQ subject');
        }

        // Set Public Key
        if (_context.bindings.X509_REQ_set_pubkey(req, keyPair.handle) != 1) {
            throw OpenSslException('Failed to set X509_REQ public key');
        }

        // Sign
        final digestLabel = digestName.toNativeUtf8(allocator: calloc);
        final md = _context.bindings.EVP_get_digestbyname(digestLabel.cast());
        calloc.free(digestLabel);
        
        if (md == nullptr) throw OpenSslException('Unknown digest: $digestName');

        // Note: X509_REQ_sign returns the size of the signature on success, or 0 on failure.
        if (_context.bindings.X509_REQ_sign(req, keyPair.handle, md) == 0) {
             throw OpenSslException('Failed to sign X509_REQ');
        }

        return X509Request(req, _context);

    } catch (e) {
        _context.bindings.X509_REQ_free(req);
        rethrow;
    }
  }
}
