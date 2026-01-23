import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../crypto/evp_pkey.dart';
import '../infra/ssl_exception.dart';
import '../infra/ssl_object.dart';

/// CMS/PKCS#7 signer using OpenSSL CMS APIs (ASN.1 handled by OpenSSL).
class CmsPkcs7Signer {
  final OpenSSL _openSsl;

  static const String _oidData = '1.2.840.113549.1.7.1';
  static const String _oidAttrContentType = '1.2.840.113549.1.9.3';
  static const String _oidAttrMessageDigest = '1.2.840.113549.1.9.4';

  CmsPkcs7Signer(this._openSsl);

  /// Generates a detached CMS/PKCS#7 signature (DER) for [content].
  Uint8List signDetached({
    required Uint8List content,
    required Uint8List certificateDer,
    required EvpPkey privateKey,
    List<Uint8List> extraCertsDer = const [],
    String hashAlgorithm = 'SHA256',
  }) {
    final bindings = _openSsl.bindings;

    // Evita “lixo” na error queue afetar checagens posteriores.
    OpenSslException.clearError(bindings);

    final certPtr = _d2iX509(certificateDer);
    final extraCertPtrs = <Pointer<X509>>[];

    Pointer<CMS_ContentInfo> cms = nullptr;
    Pointer<BIO> dataBio = nullptr;

    try {
      final md = _getDigestByName(hashAlgorithm);

      cms = bindings.CMS_sign(
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CMS_PARTIAL | CMS_BINARY | CMS_DETACHED,
      );
      if (cms == nullptr) {
        throw OpenSslException('CMS_sign (partial) failed');
      }

      final signerInfo = bindings.CMS_add1_signer(
        cms,
        certPtr,
        privateKey.handle,
        md,
        0,
      );
      if (signerInfo == nullptr) {
        throw OpenSslException('CMS_add1_signer failed');
      }

      // IMPORTANTE:
      // Não chame CMS_add1_cert(cms, certPtr) aqui.
      // Em OpenSSL (especialmente 3.x), CMS_add1_signer normalmente já inclui
      // o certificado do signer no CMS, e adicionar de novo pode falhar com:
      // "certificate already present" (0x170000AF).

      // Adiciona apenas certificados extras (cadeia), se fornecidos.
      for (final der in extraCertsDer) {
        final extraPtr = _d2iX509(der);
        extraCertPtrs.add(extraPtr);

        OpenSslException.clearError(bindings);
        SslObject.checkCode(
          bindings,
          bindings.CMS_add1_cert(cms, extraPtr),
          msg: 'CMS_add1_cert (extra) failed',
        );
      }

      dataBio = _bioFromBytes(content);

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_final(
          cms,
          dataBio,
          nullptr,
          CMS_BINARY | CMS_DETACHED,
        ),
        msg: 'CMS_final failed',
      );

      OpenSslException.clearError(bindings);
      return _i2dCms(cms);
    } finally {
      if (dataBio != nullptr) {
        bindings.BIO_free(dataBio);
      }
      if (cms != nullptr) {
        bindings.CMS_ContentInfo_free(cms);
      }
      for (final p in extraCertPtrs) {
        bindings.X509_free(p);
      }
      if (certPtr != nullptr) {
        bindings.X509_free(certPtr);
      }
    }
  }

  /// Generates a detached CMS/PKCS#7 signature (DER) using a precomputed hash.
  ///
  /// The signature is computed over SignedAttributes that contain the
  /// `contentType` and `messageDigest` attributes, where `messageDigest`
  /// is the provided [contentDigest].
  Uint8List signDetachedDigest({
    required Uint8List contentDigest,
    required Uint8List certificateDer,
    required EvpPkey privateKey,
    List<Uint8List> extraCertsDer = const [],
    String hashAlgorithm = 'SHA256',
  }) {
    final bindings = _openSsl.bindings;

    OpenSslException.clearError(bindings);

    final certPtr = _d2iX509(certificateDer);
    final extraCertPtrs = <Pointer<X509>>[];

    Pointer<CMS_ContentInfo> cms = nullptr;
    Pointer<CMS_SignerInfo> signerInfo = nullptr;
    Pointer<ASN1_OBJECT> oidData = nullptr;
    Pointer<ASN1_OBJECT> oidAttrContentType = nullptr;
    Pointer<ASN1_OBJECT> oidAttrMessageDigest = nullptr;
    Pointer<Uint8> digestPtr = nullptr;

    try {
      final md = _getDigestByName(hashAlgorithm);

      cms = bindings.CMS_sign(
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CMS_PARTIAL | CMS_BINARY | CMS_DETACHED,
      );
      if (cms == nullptr) {
        throw OpenSslException('CMS_sign (partial) failed');
      }

      signerInfo = bindings.CMS_add1_signer(
        cms,
        certPtr,
        privateKey.handle,
        md,
        0,
      );
      if (signerInfo == nullptr) {
        throw OpenSslException('CMS_add1_signer failed');
      }

      // Mesmo motivo do signDetached(): não adicione o cert do signer manualmente.
      for (final der in extraCertsDer) {
        final extraPtr = _d2iX509(der);
        extraCertPtrs.add(extraPtr);

        OpenSslException.clearError(bindings);
        SslObject.checkCode(
          bindings,
          bindings.CMS_add1_cert(cms, extraPtr),
          msg: 'CMS_add1_cert (extra) failed',
        );
      }

      oidData = _objFromText(_oidData);
      oidAttrContentType = _objFromText(_oidAttrContentType);
      oidAttrMessageDigest = _objFromText(_oidAttrMessageDigest);

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_signed_add1_attr_by_OBJ(
          signerInfo,
          oidAttrContentType,
          V_ASN1_OBJECT,
          oidData.cast(),
          -1,
        ),
        msg: 'CMS_signed_add1_attr_by_OBJ (contentType) failed',
      );

      digestPtr = calloc<Uint8>(contentDigest.length);
      digestPtr.asTypedList(contentDigest.length).setAll(0, contentDigest);

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_signed_add1_attr_by_OBJ(
          signerInfo,
          oidAttrMessageDigest,
          V_ASN1_OCTET_STRING,
          digestPtr.cast(),
          contentDigest.length,
        ),
        msg: 'CMS_signed_add1_attr_by_OBJ (messageDigest) failed',
      );

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_SignerInfo_sign(signerInfo),
        msg: 'CMS_SignerInfo_sign failed',
      );

      OpenSslException.clearError(bindings);
      return _i2dCms(cms);
    } finally {
      if (digestPtr != nullptr) {
        calloc.free(digestPtr);
      }
      if (oidAttrMessageDigest != nullptr) {
        bindings.ASN1_OBJECT_free(oidAttrMessageDigest);
      }
      if (oidAttrContentType != nullptr) {
        bindings.ASN1_OBJECT_free(oidAttrContentType);
      }
      if (oidData != nullptr) {
        bindings.ASN1_OBJECT_free(oidData);
      }
      if (cms != nullptr) {
        bindings.CMS_ContentInfo_free(cms);
      }
      for (final p in extraCertPtrs) {
        bindings.X509_free(p);
      }
      if (certPtr != nullptr) {
        bindings.X509_free(certPtr);
      }
    }
  }

  /// Generates a detached CMS/PKCS#7 signature (DER) using a precomputed hash
  /// and a provided X509 pointer (avoids DER decoding).
  Uint8List signDetachedDigestWithCert({
    required Uint8List contentDigest,
    required Pointer<X509> certificate,
    required EvpPkey privateKey,
    List<Uint8List> extraCertsDer = const [],
    String hashAlgorithm = 'SHA256',
  }) {
    final bindings = _openSsl.bindings;

    OpenSslException.clearError(bindings);

    final extraCertPtrs = <Pointer<X509>>[];

    Pointer<CMS_ContentInfo> cms = nullptr;
    Pointer<CMS_SignerInfo> signerInfo = nullptr;
    Pointer<ASN1_OBJECT> oidData = nullptr;
    Pointer<ASN1_OBJECT> oidAttrContentType = nullptr;
    Pointer<ASN1_OBJECT> oidAttrMessageDigest = nullptr;
    Pointer<Uint8> digestPtr = nullptr;

    try {
      final md = _getDigestByName(hashAlgorithm);

      cms = bindings.CMS_sign(
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CMS_PARTIAL | CMS_BINARY | CMS_DETACHED,
      );
      if (cms == nullptr) {
        throw OpenSslException('CMS_sign (partial) failed');
      }

      signerInfo = bindings.CMS_add1_signer(
        cms,
        certificate,
        privateKey.handle,
        md,
        0,
      );
      if (signerInfo == nullptr) {
        throw OpenSslException('CMS_add1_signer failed');
      }

      // Add extra certs if any.
      for (final der in extraCertsDer) {
        final extraPtr = _d2iX509(der);
        extraCertPtrs.add(extraPtr);

        OpenSslException.clearError(bindings);
        SslObject.checkCode(
          bindings,
          bindings.CMS_add1_cert(cms, extraPtr),
          msg: 'CMS_add1_cert (extra) failed',
        );
      }

      oidData = _objFromText(_oidData);
      oidAttrContentType = _objFromText(_oidAttrContentType);
      oidAttrMessageDigest = _objFromText(_oidAttrMessageDigest);

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_signed_add1_attr_by_OBJ(
          signerInfo,
          oidAttrContentType,
          V_ASN1_OBJECT,
          oidData.cast(),
          -1,
        ),
        msg: 'CMS_signed_add1_attr_by_OBJ (contentType) failed',
      );

      digestPtr = calloc<Uint8>(contentDigest.length);
      digestPtr.asTypedList(contentDigest.length).setAll(0, contentDigest);

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_signed_add1_attr_by_OBJ(
          signerInfo,
          oidAttrMessageDigest,
          V_ASN1_OCTET_STRING,
          digestPtr.cast(),
          contentDigest.length,
        ),
        msg: 'CMS_signed_add1_attr_by_OBJ (messageDigest) failed',
      );

      OpenSslException.clearError(bindings);
      SslObject.checkCode(
        bindings,
        bindings.CMS_SignerInfo_sign(signerInfo),
        msg: 'CMS_SignerInfo_sign failed',
      );

      OpenSslException.clearError(bindings);
      return _i2dCms(cms);
    } finally {
      if (digestPtr != nullptr) {
        calloc.free(digestPtr);
      }
      if (oidAttrMessageDigest != nullptr) {
        bindings.ASN1_OBJECT_free(oidAttrMessageDigest);
      }
      if (oidAttrContentType != nullptr) {
        bindings.ASN1_OBJECT_free(oidAttrContentType);
      }
      if (oidData != nullptr) {
        bindings.ASN1_OBJECT_free(oidData);
      }
      if (cms != nullptr) {
        bindings.CMS_ContentInfo_free(cms);
      }
      for (final p in extraCertPtrs) {
        bindings.X509_free(p);
      }
    }
  }

  Pointer<X509> _d2iX509(Uint8List der) {
    final dataPtr = calloc<Uint8>(der.length);
    dataPtr.asTypedList(der.length).setAll(0, der);

    final pp = calloc<Pointer<UnsignedChar>>();
    pp.value = dataPtr.cast<UnsignedChar>();

    final cert = _openSsl.bindings.d2i_X509(nullptr, pp, der.length);

    calloc.free(pp);
    calloc.free(dataPtr);

    if (cert == nullptr) {
      throw OpenSslException('d2i_X509 failed');
    }

    return cert;
  }

  Pointer<BIO> _bioFromBytes(Uint8List data) {
    final bio = _openSsl.bindings.BIO_new(_openSsl.bindings.BIO_s_mem());
    if (bio == nullptr) {
      throw OpenSslException('BIO_new failed');
    }

    final buffer = calloc<Uint8>(data.length);
    try {
      buffer.asTypedList(data.length).setAll(0, data);
      final written = _openSsl.bindings.BIO_write(
        bio,
        buffer.cast(),
        data.length,
      );
      if (written <= 0) {
        throw OpenSslException('BIO_write failed');
      }
    } finally {
      calloc.free(buffer);
    }

    return bio;
  }

  Pointer<EVP_MD> _getDigestByName(String name) {
    final cname = name.toNativeUtf8(allocator: calloc);
    try {
      final md = _openSsl.bindings.EVP_get_digestbyname(cname.cast());
      if (md == nullptr) {
        throw OpenSslException('Unknown digest algorithm: $name');
      }
      return md;
    } finally {
      calloc.free(cname);
    }
  }

  Pointer<ASN1_OBJECT> _objFromText(String oid) {
    final oidPtr = oid.toNativeUtf8(allocator: calloc);
    try {
      final obj = _openSsl.bindings.OBJ_txt2obj(oidPtr.cast(), 1);
      if (obj == nullptr) {
        throw OpenSslException('OBJ_txt2obj failed for OID: $oid');
      }
      return obj;
    } finally {
      calloc.free(oidPtr);
    }
  }

  Uint8List _i2dCms(Pointer<CMS_ContentInfo> cms) {
    final len = _openSsl.bindings.i2d_CMS_ContentInfo(cms, nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_CMS_ContentInfo length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    final written = _openSsl.bindings.i2d_CMS_ContentInfo(cms, out);
    calloc.free(out);

    if (written <= 0) {
      calloc.free(buffer);
      throw OpenSslException('i2d_CMS_ContentInfo encode failed');
    }

    final bytes = Uint8List.fromList(buffer.asTypedList(written));
    calloc.free(buffer);
    return bytes;
  }
}
