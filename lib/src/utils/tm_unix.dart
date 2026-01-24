import 'dart:ffi';
import 'package:ffi/ffi.dart';

/// Unix/Linux (glibc) struct tm: 9 ints + long tm_gmtoff + char* tm_zone
final class TmUnix extends Struct {
  @Int32() external int tm_sec;
  @Int32() external int tm_min;
  @Int32() external int tm_hour;
  @Int32() external int tm_mday;
  @Int32() external int tm_mon;
  @Int32() external int tm_year;
  @Int32() external int tm_wday;
  @Int32() external int tm_yday;
  @Int32() external int tm_isdst;
  // glibc extras:
  @IntPtr() external int tm_gmtoff;  // long
  external Pointer<Utf8> tm_zone;    // char*
}
