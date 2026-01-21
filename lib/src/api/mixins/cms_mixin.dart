import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../openssl.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../cms/cms_content.dart';
import '../../x509/x509_certificate.dart';
import '../../x509/x509_store.dart';
import '../../crypto/evp_pkey.dart';

/// Mixin for CMS/PKCS#7 high-level operations.
mixin CmsMixin on OpenSslContext {
  /// Generates a CMS/PKCS#7 signature for a pre-calculated [digest].
  /// [digest] must be the SHA-256 hash of the content (32 bytes).
  Uint8List signDetachedDigest({
    required Uint8List digest,
    required X509Certificate certificate,
    required EvpPkey privateKey,
  }) {
    if (digest.length != 32) {
       throw ArgumentError('Digest must be 32 bytes (SHA-256)');
    }

    // 1. Create Partial CMS
    final cms = bindings.CMS_sign(
      nullptr, 
      nullptr, 
      nullptr, 
      nullptr, 
      CMS_PARTIAL | CMS_DETACHED | CMS_BINARY
    );
    if (cms == nullptr) throw OpenSslException('CMS_sign init failed');

    try {
      // 2. Add Signer
      final signCert = certificate.handle;
      final pkey = privateKey.handle;
      final sha256 = bindings.EVP_sha256();

      // flag CMS_KEYID? or CMS_ISSUER_AND_SERIAL (default).
      final si = bindings.CMS_add1_signer(cms, signCert, pkey, sha256, 0);
      if (si == nullptr) throw OpenSslException('CMS_add1_signer failed');

      if (bindings.CMS_add1_cert(cms, signCert) != 1) {
         throw OpenSslException('CMS_add1_cert failed');
      }

      // 3. Add Attributes: Content-Type
      final ctCStr = '1.2.840.113549.1.9.3'.toNativeUtf8(allocator: calloc);
      final oidContentType = bindings.OBJ_txt2obj(ctCStr.cast(), 1); 
      calloc.free(ctCStr);
      if (oidContentType == nullptr) throw OpenSslException('Failed to create OID Content-Type');
      
      // pkcs7-data = 1.2.840.113549.1.7.1
      final dataCStr = '1.2.840.113549.1.7.1'.toNativeUtf8(allocator: calloc);
      final oidData = bindings.OBJ_txt2obj(dataCStr.cast(), 1);
      calloc.free(dataCStr);
      if (oidData == nullptr) throw OpenSslException('Failed to create OID Data');

      final resultCT = bindings.CMS_signed_add1_attr_by_OBJ(
        si, 
        oidContentType, 
        V_ASN1_OBJECT, 
        oidData.cast(), 
        -1
      );
      if (resultCT != 1) throw OpenSslException('Failed to add Content-Type attribute');
      bindings.ASN1_OBJECT_free(oidContentType);
      // oidData owned by attribute now? No, add1 copies.
      bindings.ASN1_OBJECT_free(oidData);

      // 4. Add Attributes: Message-Digest
      final mdCStr = '1.2.840.113549.1.9.4'.toNativeUtf8(allocator: calloc);
      final oidMsgDigest = bindings.OBJ_txt2obj(mdCStr.cast(), 1);
      calloc.free(mdCStr);
      if (oidMsgDigest == nullptr) throw OpenSslException('Failed to create OID Message-Digest');
      
      // We pass the raw bytes for V_ASN1_OCTET_STRING. 
      // The function will create the ASN1_OCTET_STRING internally.
      final digestPtr = calloc<Uint8>(digest.length);
      final digestList = digestPtr.asTypedList(digest.length);
      digestList.setAll(0, digest);

      final resultMD = bindings.CMS_signed_add1_attr_by_OBJ(
        si,
        oidMsgDigest,
        V_ASN1_OCTET_STRING,
        digestPtr.cast(),
        digest.length
      );
      
      calloc.free(digestPtr);

      if (resultMD != 1) throw OpenSslException('Failed to add Message-Digest attribute');
      
      bindings.ASN1_OBJECT_free(oidMsgDigest);
      // bindings.ASN1_OCTET_STRING_free(digestOctet); // No longer used

      // 5. Finalize (Sign attributes)
      // Since attributes are present, CMS_final will sign them without hashing data.
      // We pass nullptr as data.
      if (bindings.CMS_final(cms, nullptr, nullptr, CMS_DETACHED | CMS_BINARY) != 1) {
         final err = bindings.ERR_get_error();
         final strPtr = bindings.ERR_error_string(err, nullptr);
         final errMsg = strPtr == nullptr ? 'Unknown error' : strPtr.cast<Utf8>().toDartString();
         throw OpenSslException('CMS_final failed: $errMsg ($err)');
      }

      // 6. Encode
      return encodeCms(CmsContent(cms, this as OpenSSL));
    } catch (e) {
      bindings.CMS_ContentInfo_free(cms);
      rethrow;
    }
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
        nullptr,
        storePtr,
        dataBio,
        nullptr,
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
