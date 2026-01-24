import 'dart:ffi';
import 'package:openssl_bindings/src/generated/ffi.dart';

void main() {
  print('sizeof tm = ${sizeOf<tm>()}');
  print('sizeof v3_ext_ctx = ${sizeOf<v3_ext_ctx>()}');
  print('sizeof X509V3_CTX = ${sizeOf<X509V3_CTX>()}');
}
