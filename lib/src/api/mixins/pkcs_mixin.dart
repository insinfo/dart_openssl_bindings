import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../openssl_context.dart';
import '../openssl.dart';
import '../../generated/ffi.dart';
import '../../infra/ssl_exception.dart';
import '../../crypto/evp_pkey.dart';
import '../../x509/x509_certificate.dart';
import '../../pkcs/pkcs12_bundle.dart';

/// Mixin for PKCS#7 (.p7b) and PKCS#12 (.pfx/.p12) helpers.
mixin PkcsMixin on OpenSslContext {
  /// Extracts certificates from a PKCS#7/CMS DER payload (.p7b).
  List<X509Certificate> loadCertificatesFromPkcs7Der(Uint8List der) {
    final cms = _d2iCms(der);
    try {
      final stack = bindings.CMS_get1_certs(cms);
      if (stack == nullptr) return const [];
      return _x509StackToList(
        stack.cast(),
        duplicateCerts: true,
        freeStackAndCerts: true,
      );
    } finally {
      bindings.CMS_ContentInfo_free(cms);
    }
  }

  /// Extracts certificates from a PKCS#7/CMS PEM string (.p7b).
  List<X509Certificate> loadCertificatesFromPkcs7Pem(String pem) {
    return loadCertificatesFromPkcs7Der(_pemToDer(pem));
  }

  /// Extracts certificates from PKCS#7 bytes (auto-detect PEM vs DER).
  List<X509Certificate> loadCertificatesFromPkcs7Bytes(Uint8List bytes) {
    if (_looksLikePem(bytes)) {
      final pem = String.fromCharCodes(bytes);
      return loadCertificatesFromPkcs7Pem(pem);
    }
    return loadCertificatesFromPkcs7Der(bytes);
  }

  /// Parses PKCS#12/PFX (DER) and returns key, certificate and chain.
  Pkcs12Bundle parsePkcs12(Uint8List der, {String password = ''}) {
    final arena = Arena();
    Pointer<PKCS12> p12 = nullptr;

    try {
      final inPtr = arena<UnsignedChar>(der.length);
      inPtr.cast<Uint8>().asTypedList(der.length).setAll(0, der);
      final inOutPtr = arena<Pointer<UnsignedChar>>();
      inOutPtr.value = inPtr;

      p12 = bindings.d2i_PKCS12(nullptr, inOutPtr, der.length);
      if (p12 == nullptr) {
        throw OpenSslException('d2i_PKCS12 failed');
      }

      final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
      final certPtr = calloc<Pointer<X509>>();
      final caPtr = calloc<Pointer<stack_st_X509>>();
      Pointer<Char> passPtr = nullptr;

      if (password.isNotEmpty) {
        passPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
      }

      try {
        final result = bindings.PKCS12_parse(
          p12,
          passPtr,
          pkeyPtr,
          certPtr,
          caPtr,
        );
        if (result != 1) {
          throw OpenSslException('PKCS12_parse failed (check password?)');
        }

        final pkey = EvpPkey(pkeyPtr.value, this as OpenSSL);
        final cert = X509Certificate(certPtr.value, this as OpenSSL);
        final caStack = caPtr.value;
        final ca = caStack == nullptr
            ? const <X509Certificate>[]
            : _x509StackToList(
          caStack.cast<OPENSSL_STACK>(),
                duplicateCerts: false,
                freeStackOnly: true,
              );

        return Pkcs12Bundle(
          privateKey: pkey,
          certificate: cert,
          caCertificates: ca,
        );
      } finally {
        calloc.free(pkeyPtr);
        calloc.free(certPtr);
        calloc.free(caPtr);
        if (passPtr != nullptr) {
          calloc.free(passPtr);
        }
      }
    } finally {
      if (p12 != nullptr) {
        bindings.PKCS12_free(p12);
      }
      arena.releaseAll();
    }
  }

  /// Creates a PKCS#12/PFX bundle (DER) with key + certificate (+ optional chain).
  Uint8List createPkcs12({
    required EvpPkey privateKey,
    required X509Certificate certificate,
    List<X509Certificate> caCertificates = const [],
    String? password,
    String? friendlyName,
    int iterations = 2048,
    int macIterations = 2048,
  }) {
    Pointer<stack_st_X509> caStack = nullptr;
    Pointer<Char> passPtr = nullptr;
    Pointer<Char> namePtr = nullptr;

    try {
      if (password != null && password.isNotEmpty) {
        passPtr = password.toNativeUtf8(allocator: calloc).cast<Char>();
      }
      if (friendlyName != null && friendlyName.isNotEmpty) {
        namePtr = friendlyName.toNativeUtf8(allocator: calloc).cast<Char>();
      }

      if (caCertificates.isNotEmpty) {
        caStack = _createX509Stack(caCertificates);
      }

      final pkcs12 = bindings.PKCS12_create(
        passPtr,
        namePtr,
        privateKey.handle,
        certificate.handle,
        caStack,
        0,
        0,
        iterations,
        macIterations,
        0,
      );

      if (pkcs12 == nullptr) {
        throw OpenSslException('PKCS12_create failed');
      }

      try {
        return _i2dPkcs12(pkcs12);
      } finally {
        bindings.PKCS12_free(pkcs12);
      }
    } finally {
      if (caStack != nullptr) {
        _freeX509StackAndCerts(caStack.cast<OPENSSL_STACK>());
      }
      if (passPtr != nullptr) {
        calloc.free(passPtr);
      }
      if (namePtr != nullptr) {
        calloc.free(namePtr);
      }
    }
  }

  Pointer<CMS_ContentInfo> _d2iCms(Uint8List der) {
    final arena = Arena();
    try {
      final inPtr = arena<UnsignedChar>(der.length);
      inPtr.cast<Uint8>().asTypedList(der.length).setAll(0, der);
      final inOutPtr = arena<Pointer<UnsignedChar>>();
      inOutPtr.value = inPtr;

      final cms = bindings.d2i_CMS_ContentInfo(nullptr, inOutPtr, der.length);
      if (cms == nullptr) {
        throw OpenSslException('d2i_CMS_ContentInfo failed');
      }
      return cms;
    } finally {
      arena.releaseAll();
    }
  }

  Uint8List _i2dPkcs12(Pointer<PKCS12> p12) {
    final len = bindings.i2d_PKCS12(p12, nullptr);
    if (len <= 0) {
      throw OpenSslException('i2d_PKCS12 length failed');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    final written = bindings.i2d_PKCS12(p12, out);
    calloc.free(out);

    if (written <= 0) {
      calloc.free(buffer);
      throw OpenSslException('i2d_PKCS12 encode failed');
    }

    final bytes = Uint8List.fromList(buffer.asTypedList(written));
    calloc.free(buffer);
    return bytes;
  }

  Pointer<stack_st_X509> _createX509Stack(
    List<X509Certificate> certificates,
  ) {
    final stack = bindings.OPENSSL_sk_new_null();
    if (stack == nullptr) {
      throw OpenSslException('OPENSSL_sk_new_null failed');
    }

    for (final cert in certificates) {
      if (bindings.X509_up_ref(cert.handle) != 1) {
        throw OpenSslException('X509_up_ref failed');
      }
      final pushResult = bindings.OPENSSL_sk_push(
        stack.cast(),
        cert.handle.cast(),
      );
      if (pushResult == 0) {
        throw OpenSslException('OPENSSL_sk_push failed');
      }
    }

    return stack.cast<stack_st_X509>();
  }

  List<X509Certificate> _x509StackToList(
    Pointer<OPENSSL_STACK> stack, {
    required bool duplicateCerts,
    bool freeStackAndCerts = false,
    bool freeStackOnly = false,
  }) {
    final count = bindings.OPENSSL_sk_num(stack.cast());
    final result = <X509Certificate>[];

    for (var i = 0; i < count; i++) {
      final value = bindings.OPENSSL_sk_value(stack.cast(), i);
      if (value == nullptr) continue;

      final certPtr = value.cast<X509>();
      Pointer<X509> handle = certPtr;

      if (duplicateCerts) {
        final dup = bindings.X509_dup(certPtr);
        if (dup == nullptr) continue;
        handle = dup;
      }

      result.add(X509Certificate(handle, this as OpenSSL));
    }

    if (freeStackAndCerts) {
      _freeX509StackAndCerts(stack);
    } else if (freeStackOnly) {
      bindings.OPENSSL_sk_free(stack.cast());
    }

    return result;
  }

  void _freeX509StackAndCerts(Pointer<OPENSSL_STACK> stack) {
    final freePtr = lookup<Void Function(Pointer<X509>)>('X509_free')
        .cast<NativeFunction<Void Function(Pointer<Void>)>>();
    bindings.OPENSSL_sk_pop_free(stack.cast(), freePtr);
  }

  bool _looksLikePem(Uint8List bytes) {
    final text = String.fromCharCodes(bytes);
    return text.contains('-----BEGIN');
  }

  Uint8List _pemToDer(String pem) {
    final lines = pem
        .split(RegExp(r'\r?\n'))
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty && !line.startsWith('-----'))
        .toList();

    if (lines.isEmpty) {
      throw ArgumentError('Invalid PEM content');
    }

    final base64Data = lines.join();
    return Uint8List.fromList(base64Decode(base64Data));
  }
}
