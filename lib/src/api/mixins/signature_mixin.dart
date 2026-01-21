import 'dart:ffi'; 
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../openssl_context.dart';
import '../../crypto/evp_pkey.dart';
import '../../infra/ssl_exception.dart';
import '../../infra/ssl_object.dart';

mixin SignatureMixin on OpenSslContext {
  /// Signs [data] using the private [key].
  ///
  /// [algorithm] defaults to 'SHA256'.
  Uint8List sign(EvpPkey key, Uint8List data, {String algorithm = 'SHA256'}) {
    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    try {
      final digestName = algorithm.toNativeUtf8(allocator: calloc);
      final md = bindings.EVP_get_digestbyname(digestName.cast());
      calloc.free(digestName);

      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $algorithm');
      }

      final initResult = bindings.EVP_DigestSignInit(
        ctx,
        nullptr,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(initResult, msg: 'EVP_DigestSignInit failed');

      // Update
      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      
      final updateResult = bindings.EVP_DigestSignUpdate(
        ctx,
        dataPtr.cast(),
        data.length,
      );
      calloc.free(dataPtr);
      SslObject.checkCode(updateResult, msg: 'EVP_DigestSignUpdate failed');

      // Final (Get Length)
      final lenPtr = calloc<Size>();
      final finalLenResult = bindings.EVP_DigestSignFinal(ctx, nullptr, lenPtr);
      SslObject.checkCode(finalLenResult, msg: 'EVP_DigestSignFinal (length) failed');

      final sigLen = lenPtr.value;
      final sigPtr = calloc<Uint8>(sigLen);

      // Final (Get Signature)
      final finalResult = bindings.EVP_DigestSignFinal(ctx, sigPtr.cast(), lenPtr);
      if (finalResult <= 0) {
        calloc.free(lenPtr);
        calloc.free(sigPtr);
        throw OpenSslException('EVP_DigestSignFinal failed');
      }

      final signature = Uint8List.fromList(sigPtr.asTypedList(lenPtr.value));
      
      calloc.free(lenPtr);
      calloc.free(sigPtr);
      
      return signature;
    } finally {
      bindings.EVP_MD_CTX_free(ctx);
    }
  }

  /// Verifies [signature] for [data] using [key].
  ///
  /// Returns true if valid, false otherwise.
  bool verify(EvpPkey key, Uint8List data, Uint8List signature, {String algorithm = 'SHA256'}) {
    final bindings = this.bindings;
    final ctx = bindings.EVP_MD_CTX_new();
    if (ctx == nullptr) {
      throw OpenSslException('Failed to create EVP_MD_CTX');
    }

    try {
      final digestName = algorithm.toNativeUtf8(allocator: calloc);
      final md = bindings.EVP_get_digestbyname(digestName.cast());
      calloc.free(digestName);

      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $algorithm');
      }

      final initResult = bindings.EVP_DigestVerifyInit(
        ctx,
        nullptr,
        md,
        nullptr,
        key.handle,
      );
      SslObject.checkCode(initResult, msg: 'EVP_DigestVerifyInit failed');

      // Update
      final dataPtr = calloc<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      
      final updateResult = bindings.EVP_DigestVerifyUpdate(
        ctx,
        dataPtr.cast(),
        data.length,
      );
      calloc.free(dataPtr);
      SslObject.checkCode(updateResult, msg: 'EVP_DigestVerifyUpdate failed');

      // Final (Verify)
      final sigPtr = calloc<Uint8>(signature.length);
      sigPtr.asTypedList(signature.length).setAll(0, signature);

      // EVP_DigestVerifyFinal returns 1 for success, 0 for failure (signature mismatch), <0 for error
      final verifyResult = bindings.EVP_DigestVerifyFinal(
        ctx,
        sigPtr.cast(),
        signature.length,
      );
      
      calloc.free(sigPtr);

      if (verifyResult == 1) return true;
      if (verifyResult == 0) return false;
      
      SslObject.checkCode(verifyResult, msg: 'EVP_DigestVerifyFinal error');
      return false; // Should satisfy analyzer
    } finally {
      bindings.EVP_MD_CTX_free(ctx);
    }
  }
}
