import 'dart:ffi';

import '../api/openssl.dart';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';

/// Wrapper around OpenSSL CMS_ContentInfo.
class CmsContent extends SslObject<CMS_ContentInfo> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  CmsContent(Pointer<CMS_ContentInfo> ptr, this._context) : super(ptr) {
    final freePtr =
        _context.lookup<Void Function(Pointer<CMS_ContentInfo>)>('CMS_ContentInfo_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    attachFinalizer(_finalizer, ptr.cast());
  }
}
