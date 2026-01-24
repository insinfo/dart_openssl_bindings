import 'dart:ffi';

/// Windows (MSVCRT) struct tm: 9 int fields = 36 bytes
final class TmWindows extends Struct {
  @Int32() external int tm_sec;
  @Int32() external int tm_min;
  @Int32() external int tm_hour;
  @Int32() external int tm_mday;
  @Int32() external int tm_mon;
  @Int32() external int tm_year;
  @Int32() external int tm_wday;
  @Int32() external int tm_yday;
  @Int32() external int tm_isdst;
}
