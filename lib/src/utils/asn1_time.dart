import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import '../generated/ffi.dart';
import 'tm_unix.dart';
import 'tm_windows.dart';

/// Calculates the native size of struct tm for proper allocation.
/// Windows (MSVCRT): 36 bytes (9 int fields)
/// Unix/Linux (glibc): 56 bytes (9 ints + long tm_gmtoff + char* tm_zone)
int tmNativeBytes() {
  if (Platform.isWindows) return sizeOf<TmWindows>();
  return sizeOf<TmUnix>();
}

/// Allocates a buffer large enough for struct tm on all platforms.
Pointer<tm> allocTmCompat() {
  final raw = calloc<Uint8>(tmNativeBytes());
  return raw.cast<tm>();
}

/// Frees the buffer allocated by [allocTmCompat].
void freeTmCompat(Pointer<tm> tmPtr) {
  calloc.free(tmPtr.cast<Uint8>());
}

/// Converts an OpenSSL ASN1_TIME (UTCTime or GeneralizedTime) into a UTC
/// [DateTime].
///
/// Returns `null` when [timePtr] is `nullptr` — optional fields such as a CRL
/// nextUpdate may be absent — or when OpenSSL cannot parse the value.
DateTime? parseAsn1Time(OpenSslFfi bindings, Pointer<ASN1_TIME> timePtr) {
  if (timePtr == nullptr) return null;

  final tmPtr = allocTmCompat();
  try {
    final success = bindings.ASN1_TIME_to_tm(timePtr, tmPtr);
    if (success != 1) return null;

    final t = tmPtr.ref;
    return DateTime.utc(
      // tm_year is years since 1900, tm_mon is 0-11.
      t.tm_year + 1900,
      t.tm_mon + 1,
      t.tm_mday,
      t.tm_hour,
      t.tm_min,
      t.tm_sec,
    );
  } finally {
    freeTmCompat(tmPtr);
  }
}
