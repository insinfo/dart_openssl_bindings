import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../openssl.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../cms/cms_content.dart';
import '../../cms/cms_pkcs7_signer.dart';
import '../../cms/cms_validation_result.dart'; // import validation result
import '../../x509/x509_certificate.dart';
import '../../x509/x509_store.dart';
import '../../crypto/evp_pkey.dart';

/// Mixin for CMS/PKCS#7 high-level operations.
mixin CmsMixin on OpenSslContext {
  /// Generates a detached CMS/PKCS#7 signature (DER) for [content].
  Uint8List signDetached({
    required Uint8List content,
    required X509Certificate certificate,
    required EvpPkey privateKey,
    List<Uint8List> extraCertsDer = const [],
    String? hashAlgorithm,
  }) {
    if (hashAlgorithm != null && hashAlgorithm.isNotEmpty) {
      final digestBytes = (this as OpenSSL)
          .digest(hashAlgorithm, Uint8List.fromList(content));
      final signer = CmsPkcs7Signer(this as OpenSSL);
      return signer.signDetachedDigestWithCert(
        contentDigest: digestBytes,
        certificate: certificate.handle,
        privateKey: privateKey,
        extraCertsDer: extraCertsDer,
        hashAlgorithm: hashAlgorithm,
      );
    }

    final dataBio = _bioFromBytes(bindings, content);
    final cms = bindings.CMS_sign(
      certificate.handle,
      privateKey.handle,
      nullptr,
      dataBio,
      CMS_DETACHED | CMS_BINARY,
    );

    bindings.BIO_free(dataBio);

    if (cms == nullptr) {
      throw OpenSslException('CMS_sign failed');
    }

    final extraCertPtrs = <Pointer<X509>>[];

    try {
      // Ensure signer certificate is included in CMS.
      OpenSslException.clearError(bindings);
      if (bindings.CMS_add1_cert(cms, certificate.handle) != 1) {
        throw OpenSslException('CMS_add1_cert failed for signer');
      }

      if (extraCertsDer.isNotEmpty) {
        for (final der in extraCertsDer) {
          final extraPtr = _d2iX509(bindings, der);
          extraCertPtrs.add(extraPtr);
          OpenSslException.clearError(bindings);
          if (bindings.CMS_add1_cert(cms, extraPtr) != 1) {
            throw OpenSslException('CMS_add1_cert failed for extra cert');
          }
        }
      }

      return encodeCms(CmsContent(cms, this as OpenSSL));
    } catch (e) {
      bindings.CMS_ContentInfo_free(cms);
      rethrow;
    } finally {
      for (final p in extraCertPtrs) {
        bindings.X509_free(p);
      }
    }
  }

  /// Generates a detached CMS/PKCS#7 signature and returns CmsContent.
  CmsContent signDetachedContentInfo({
    required Uint8List content,
    required X509Certificate certificate,
    required EvpPkey privateKey,
  }) {
    final dataBio = _bioFromBytes(bindings, content);
    final cms = bindings.CMS_sign(
      certificate.handle,
      privateKey.handle,
      nullptr,
      dataBio,
      CMS_DETACHED | CMS_BINARY,
    );

    bindings.BIO_free(dataBio);

    if (cms == nullptr) {
      throw OpenSslException('CMS_sign failed');
    }

    // Ensure signer certificate is included in CMS.
    OpenSslException.clearError(bindings);
    bindings.CMS_add1_cert(cms, certificate.handle);

    return CmsContent(cms, this as OpenSSL);
  }
  /// Generates a CMS/PKCS#7 signature for a pre-calculated [digest].
  /// [digest] must be the SHA-256 hash of the content (32 bytes).
  Uint8List signDetachedDigest({
    required Uint8List digest,
    required X509Certificate certificate,
    required EvpPkey privateKey,
    List<Uint8List> extraCertsDer = const [],
    String hashAlgorithm = 'SHA256',
  }) {
    final signer = CmsPkcs7Signer(this as OpenSSL);
    return signer.signDetachedDigestWithCert(
      contentDigest: digest,
      certificate: certificate.handle,
      privateKey: privateKey,
      extraCertsDer: extraCertsDer,
      hashAlgorithm: hashAlgorithm,
    );
  }

  /// Decodes a DER CMS/PKCS#7 into a managed [CmsContent] wrapper.
  CmsContent decodeCms(Uint8List der) {
    final cmsPtr = _d2iCms(bindings, der);
    return CmsContent(cmsPtr, this as dynamic);
  }


  /// Encodes a CMS/PKCS#7 structure to DER.
  Uint8List encodeCms(CmsContent cms) {
    final len = bindings.i2d_CMS_ContentInfo(cms.handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_CMS_ContentInfo length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    final written = bindings.i2d_CMS_ContentInfo(cms.handle, out);
    calloc.free(out);

    if (written <= 0) {
      calloc.free(buffer);
      throw OpenSslException('i2d_CMS_ContentInfo encode failed');
    }

    final bytes = Uint8List.fromList(buffer.asTypedList(written));
    calloc.free(buffer);
    return bytes;
  }

  /// Verifies a detached CMS/PKCS#7 signature using the provided content and
  /// a trusted [store] or a specific [trustedCertDer].
  bool verifyCmsDetached({
    required Uint8List cmsDer,
    required Uint8List content,
    X509Store? store,
    Uint8List? trustedCertDer,
  }) {
    if (store == null && trustedCertDer == null) {
      throw ArgumentError('Either store or trustedCertDer must be provided.');
    }

    final bindings = this.bindings;

    Pointer<CMS_ContentInfo> cms = nullptr;
    Pointer<X509_STORE> tempStore = nullptr;
    Pointer<X509> cert = nullptr;
    Pointer<BIO> dataBio = nullptr;

    try {
      cms = _d2iCms(bindings, cmsDer);
      
      Pointer<X509_STORE> storePtr;

      if (store != null) {
        storePtr = store.handle;
      } else {
        // Create temporary store for single cert
        cert = _d2iX509(bindings, trustedCertDer!);
        tempStore = bindings.X509_STORE_new();
        if (tempStore == nullptr) {
          throw OpenSslException('X509_STORE_new failed');
        }
        if (bindings.X509_STORE_add_cert(tempStore, cert) != 1) {
          throw OpenSslException('X509_STORE_add_cert failed');
        }
        storePtr = tempStore;
      }

      dataBio = _bioFromBytes(bindings, content);

      final result = bindings.CMS_verify(
        cms,
        nullptr, // certs (if we want to pass extra certs explicitly, but usually they are in cms or store)
        storePtr,
        dataBio,
        nullptr, // out (we don't need output content)
        CMS_BINARY | CMS_DETACHED,
      );

      return result == 1;
    } finally {
      if (dataBio != nullptr) {
        bindings.BIO_free(dataBio);
      }
      if (tempStore != nullptr) {
        bindings.X509_STORE_free(tempStore);
      }
      if (cert != nullptr) {
        bindings.X509_free(cert);
      }
      if (cms != nullptr) {
        bindings.CMS_ContentInfo_free(cms);
      }
    }
  }

  /// Verifies a detached CMS signature using a provided CmsContent.
  bool verifyCmsDetachedContentInfo({
    required CmsContent cms,
    required Uint8List content,
    X509Store? store,
    Uint8List? trustedCertDer,
    bool skipSignerCertVerify = false,
  }) {
    if (!skipSignerCertVerify && store == null && trustedCertDer == null) {
      throw ArgumentError('Either store or trustedCertDer must be provided.');
    }

    final bindings = this.bindings;

    Pointer<X509_STORE> tempStore = nullptr;
    Pointer<X509> cert = nullptr;
    Pointer<BIO> dataBio = nullptr;

    try {
      Pointer<X509_STORE> storePtr;

      if (store != null) {
        storePtr = store.handle;
      } else if (trustedCertDer != null) {
        cert = _d2iX509(bindings, trustedCertDer);
        tempStore = bindings.X509_STORE_new();
        if (tempStore == nullptr) {
          throw OpenSslException('X509_STORE_new failed');
        }
        if (bindings.X509_STORE_add_cert(tempStore, cert) != 1) {
          throw OpenSslException('X509_STORE_add_cert failed');
        }
        storePtr = tempStore;
      } else {
        // Signature-only verification without chain validation.
        tempStore = bindings.X509_STORE_new();
        if (tempStore == nullptr) {
          throw OpenSslException('X509_STORE_new failed');
        }
        storePtr = tempStore;
      }

      dataBio = _bioFromBytes(bindings, content);

      var flags = CMS_BINARY | CMS_DETACHED;
      if (skipSignerCertVerify) {
        flags |= CMS_NO_SIGNER_CERT_VERIFY;
      }

      final result = bindings.CMS_verify(
        cms.handle,
        nullptr,
        storePtr,
        dataBio,
        nullptr,
        flags,
      );

      return result == 1;
    } finally {
      if (dataBio != nullptr) bindings.BIO_free(dataBio);
      if (tempStore != nullptr) bindings.X509_STORE_free(tempStore);
      if (cert != nullptr) bindings.X509_free(cert);
    }
  }

  /// Verifies only the signature (skips signer cert chain validation).
  bool verifyCmsDetachedSignatureOnly({
    required CmsContent cms,
    required Uint8List content,
  }) {
    return verifyCmsDetachedContentInfo(
      cms: cms,
      content: content,
      skipSignerCertVerify: true,
    );
  }

  /// Verifies signature and signer certificate chain using [store].
  bool verifyCmsDetachedFullChain({
    required CmsContent cms,
    required Uint8List content,
    required X509Store store,
  }) {
    return verifyCmsDetachedContentInfo(
      cms: cms,
      content: content,
      store: store,
      skipSignerCertVerify: false,
    );
  }

  /// Verifies a detached CMS/PKCS#7 signature and returns detailed result.
  CmsValidationResult verifyCmsDetachedWithResult({
    required Uint8List cmsDer,
    required Uint8List content,
    X509Store? store,
    Uint8List? trustedCertDer,
  }) {
    final bindings = this.bindings;
    
    // Clear error queue before starting
    while (bindings.ERR_get_error() != 0) {}

    if (store == null && trustedCertDer == null) {
      return CmsValidationResult(
        isValid: false, 
        errorMessage: 'Either store or trustedCertDer must be provided.'
      );
    }

    Pointer<CMS_ContentInfo> cms = nullptr;
    Pointer<X509_STORE> tempStore = nullptr;
    Pointer<X509> cert = nullptr;
    Pointer<BIO> dataBio = nullptr;
    
    // We need to capture errors if any step fails
    int lastError = 0;
    String? lastErrorMsg;

    try {
      // 1. Parse CMS
      try {
         cms = _d2iCms(bindings, cmsDer);
      } catch (e) {
         return CmsValidationResult(isValid: false, errorMessage: 'Invalid CMS structure: $e');
      }
      
      Pointer<X509_STORE> storePtr;

      if (store != null) {
        storePtr = store.handle;
      } else {
        // Create temporary store for single cert
        cert = _d2iX509(bindings, trustedCertDer!);
        tempStore = bindings.X509_STORE_new();
        if (tempStore == nullptr) {
           return CmsValidationResult(isValid: false, errorMessage: 'Internal Error: X509_STORE_new failed');
        }
        bindings.X509_STORE_add_cert(tempStore, cert);
        storePtr = tempStore;
      }

      dataBio = _bioFromBytes(bindings, content);

      // 2. Verify
      final result = bindings.CMS_verify(
        cms,
        nullptr,
        storePtr,
        dataBio,
        nullptr,
        CMS_BINARY | CMS_DETACHED,
      );

      if (result == 1) {
        return CmsValidationResult(isValid: true);
      } else {
        // Capture Error
        lastError = bindings.ERR_get_error();
        
        final strPtr = bindings.ERR_error_string(lastError, nullptr);
        lastErrorMsg = strPtr == nullptr 
             ? 'Unknown OpenSSL error' 
             : strPtr.cast<Utf8>().toDartString();
        
        return CmsValidationResult(
          isValid: false,
          errorCode: lastError,
          errorMessage: lastErrorMsg
        );
      }

    } catch (e) {
      return CmsValidationResult(isValid: false, errorMessage: 'Exception: $e');
    } finally {
      if (dataBio != nullptr) bindings.BIO_free(dataBio);
      if (tempStore != nullptr) bindings.X509_STORE_free(tempStore);
      if (cert != nullptr) bindings.X509_free(cert);
      if (cms != nullptr) bindings.CMS_ContentInfo_free(cms);
    }
  }

  Pointer<CMS_ContentInfo> _d2iCms(OpenSsl bindings, Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final pp = calloc<Pointer<UnsignedChar>>();
    pp.value = dataPtr.cast<UnsignedChar>();

    final cms = bindings.d2i_CMS_ContentInfo(nullptr, pp, der.length);

    calloc.free(pp);
    calloc.free(dataPtr);

    if (cms == nullptr) {
      throw OpenSslException('d2i_CMS_ContentInfo failed');
    }
    return cms;
  }

  Pointer<X509> _d2iX509(OpenSsl bindings, Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final pp = calloc<Pointer<UnsignedChar>>();
    pp.value = dataPtr.cast<UnsignedChar>();

    final cert = bindings.d2i_X509(nullptr, pp, der.length);

    calloc.free(pp);
    calloc.free(dataPtr);

    if (cert == nullptr) {
      throw OpenSslException('d2i_X509 failed');
    }
    return cert;
  }


  Pointer<BIO> _bioFromBytes(OpenSsl bindings, Uint8List data) {
    final bio = bindings.BIO_new(bindings.BIO_s_mem());
    if (bio == nullptr) {
      throw OpenSslException('BIO_new failed');
    }

    final buffer = calloc<Uint8>(data.length);
    try {
      buffer.asTypedList(data.length).setAll(0, data);
      final written = bindings.BIO_write(bio, buffer.cast(), data.length);
      if (written <= 0) {
        throw OpenSslException('BIO_write failed');
      }
    } finally {
      calloc.free(buffer);
    }

    return bio;
  }
}
