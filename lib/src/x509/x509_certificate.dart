import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../generated/ffi.dart';
import '../infra/ssl_object.dart';
import '../infra/ssl_exception.dart';
import '../api/openssl.dart';
import '../crypto/evp_pkey.dart';

import 'icp_brasil_info.dart';
import 'icp_brasil_parser.dart';
import '../utils/tm_windows.dart';
import '../utils/tm_unix.dart';
import '../utils/hex.dart';

const int BIO_CTRL_PENDING = 10;

/// Wrapper around OpenSSL X509 (Certificate).
class X509Certificate extends SslObject<X509> {
  final OpenSSL _context;
  late final NativeFinalizer _finalizer;

  X509Certificate(Pointer<X509> ptr, this._context) : super(ptr) {
    final freePtr = _context.lookup<Void Function(Pointer<X509>)>('X509_free');
    _finalizer = NativeFinalizer(freePtr.cast());
    _finalizer.attach(this, ptr.cast(), detach: this);
  }

  void dispose() {
    _finalizer.detach(this);
    _context.bindings.X509_free(handle);
  }

  /// Exports Certificate to PEM format.
  String toPem() {
    final bio = _context.createBio();
    try {
      final result = _context.bindings.PEM_write_bio_X509(bio, handle);
      if (result != 1)
        throw OpenSslException('Failed to write certificate to PEM');
      return _context.bioToString(bio);
    } finally {
      _context.freeBio(bio);
    }
  }

  /// Exports Certificate to DER bytes.
  Uint8List toDer() {
    final len = _context.bindings.i2d_X509(handle, nullptr);
    if (len <= 0) {
      throw OpenSslException('Failed to get certificate DER length');
    }

    final buffer = calloc<Uint8>(len);
    final out = calloc<Pointer<UnsignedChar>>();
    out.value = buffer.cast<UnsignedChar>();

    try {
      final written = _context.bindings.i2d_X509(handle, out);
      if (written <= 0) {
        throw OpenSslException('Failed to encode certificate to DER');
      }
      return Uint8List.fromList(buffer.asTypedList(written));
    } finally {
      calloc.free(out);
      calloc.free(buffer);
    }
  }

  /// Gets the version of the certificate.
  /// Returns 1 for V1, 3 for V3.
  int get version {
    final v = _context.bindings.X509_get_version(handle);
    return v + 1;
  }

  /// Gets the Subject DN as a string (e.g. "C=BR, O=ICP-Brasil, ...").
  String get subject {
    final namePtr = _context.bindings.X509_get_subject_name(handle);
    if (namePtr == nullptr) return '';
    return _x509NameToString(namePtr);
  }

  /// Gets the Issuer DN as a string.
  String get issuer {
    final namePtr = _context.bindings.X509_get_issuer_name(handle);
    if (namePtr == nullptr) return '';
    return _x509NameToString(namePtr);
  }

  String _x509NameToString(Pointer<X509_NAME> namePtr) {
    if (namePtr == nullptr) return '';

    final bio = _context.bindings.BIO_new(_context.bindings.BIO_s_mem());
    if (bio == nullptr) return '';

    try {
      // XN_FLAG_RFC2253 (0) -> C=BR,O=... (comma separated)
      // XN_FLAG_ONELINE (~0) ?
      // Use XN_FLAG_SEP_COMMA_PLUS (0x10000) | XN_FLAG_DN_REV (0x2000000) for RFC2253-like
      // Let's use simple RFC2253 format which is standard
      _context.bindings.X509_NAME_print_ex(
          bio, namePtr, 0, 0); // 0 indent, 0 flags (RFC2253?)

      final len = _context.bindings.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr);
      if (len <= 0) return '';

      final buffer = calloc<Uint8>(len + 1);
      try {
        _context.bindings.BIO_read(bio, buffer.cast(), len);
        return buffer.cast<Utf8>().toDartString(length: len);
      } finally {
        calloc.free(buffer);
      }
    } finally {
      _context.bindings.BIO_free(bio);
    }
  }

  /// Public key of the certificate.
  ///
  /// Returns a fresh [EvpPkey] on every call; the caller owns it and should
  /// call `dispose()` when done.
  EvpPkey get publicKey {
    final pkey = _context.bindings.X509_get_pubkey(handle);
    if (pkey == nullptr) {
      throw OpenSslException('X509_get_pubkey failed');
    }
    return EvpPkey(pkey, _context);
  }

  /// Serial number as a [BigInt], handy for matching CRL entries.
  BigInt get serialNumberBigInt {
    final decimal = serialNumber;
    if (decimal.isEmpty) return BigInt.zero;
    return BigInt.parse(decimal);
  }

  /// Gets the Serial Number as a decimal string.
  String get serialNumber {
    final asn1Int = _context.bindings.X509_get_serialNumber(handle);
    if (asn1Int == nullptr) return '';

    final bn = _context.bindings.ASN1_INTEGER_to_BN(asn1Int, nullptr);
    if (bn == nullptr) return '';

    try {
      final decPtr = _context.bindings.BN_bn2dec(bn);
      if (decPtr == nullptr) return '';

      try {
        return decPtr.cast<Utf8>().toDartString();
      } finally {
        // Safe to call CRYPTO_free on OpenSSL allocated strings
        _context.bindings.CRYPTO_free(decPtr.cast(), nullptr, 0);
      }
    } finally {
      _context.bindings.BN_free(bn);
    }
  }

  /// Valid NotBefore date (Start Date).
  DateTime? get notBefore {
    final timePtr = _context.bindings.X509_getm_notBefore(handle);
    return _parseAsn1Time(timePtr);
  }

  /// Valid NotAfter date (End Date).
  DateTime? get notAfter {
    final timePtr = _context.bindings.X509_getm_notAfter(handle);
    return _parseAsn1Time(timePtr);
  }

  /// Calculates the native size of struct tm for proper allocation.
  /// Windows (MSVCRT): 36 bytes (9 int fields)
  /// Unix/Linux (glibc): 56 bytes (9 ints + long tm_gmtoff + char* tm_zone)
  int _tmNativeBytes() {
    if (Platform.isWindows) return sizeOf<TmWindows>();
    return sizeOf<TmUnix>();
  }

  /// Allocates a buffer large enough for struct tm on all platforms.
  Pointer<tm> _allocTmCompat() {
    final bytes = _tmNativeBytes();
    final raw = calloc<Uint8>(bytes);
    return raw.cast<tm>();
  }

  /// Frees the buffer allocated by _allocTmCompat.
  void _freeTmCompat(Pointer<tm> tmPtr) {
    calloc.free(tmPtr.cast<Uint8>());
  }

  DateTime? _parseAsn1Time(Pointer<ASN1_TIME> timePtr) {
    if (timePtr == nullptr) return null;

    // Allocate a buffer large enough for struct tm on all platforms.
    // Windows (MSVCRT): 36 bytes (9 int fields)
    // Unix/Linux (glibc): ~56 bytes (9 fields + tm_gmtoff + tm_zone)
    // We calculate the size dynamically and cast to Pointer<tm> for OpenSSL.
    final tmPtr = _allocTmCompat();
    try {
      final success = _context.bindings.ASN1_TIME_to_tm(timePtr, tmPtr);
      if (success != 1) return null;

      final t = tmPtr.ref;
      // tm_year is years since 1900
      final year = t.tm_year + 1900;
      // tm_mon is 0-11
      final month = t.tm_mon + 1;

      return DateTime.utc(
        year,
        month,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
      );
    } finally {
      _freeTmCompat(tmPtr);
    }
  }

  /// Extracts ICP-Brasil fields (name, CPF/CNPJ, birth date, policies) from
  /// the certificate.
  IcpBrasilInfo extractIcpBrasilInfo() {
    final otherNames = _getSubjectAltNameOtherNames();
    final naturalPersonBlock = otherNames[IcpBrasilParser.oidNaturalPerson];
    final responsibleBlock =
        otherNames[IcpBrasilParser.oidLegalEntityResponsible];
    final subjectDn = subject;

    // The positional block of the responsible is the fallback for a legal
    // entity certificate, where the natural-person block is absent.
    final personBlock = naturalPersonBlock ?? responsibleBlock;

    return IcpBrasilInfo(
      name: _extractDnValue(subjectDn, 'CN'),
      cpf: IcpBrasilParser.extractCpf(
        subjectDn: subjectDn,
        otherNameNaturalPerson: naturalPersonBlock,
        otherNameResponsible: responsibleBlock,
      ),
      cpfOtherNameRaw: naturalPersonBlock,
      cnpj: IcpBrasilParser.extractCnpj(
        subjectDn: subjectDn,
        otherNameCnpj: otherNames[IcpBrasilParser.oidCnpj],
      ),
      birthDate: IcpBrasilParser.extractBirthDate(personBlock),
      nis: IcpBrasilParser.extractNis(personBlock),
      idCard: IcpBrasilParser.extractIdCard(personBlock),
      cei: otherNames[IcpBrasilParser.oidNaturalPersonCei] ??
          otherNames[IcpBrasilParser.oidLegalEntityCei],
      voterRegistration: otherNames[IcpBrasilParser.oidVoterRegistration],
      companyName: otherNames[IcpBrasilParser.oidCompanyName],
      responsibleName:
          otherNames[IcpBrasilParser.oidLegalEntityResponsibleName],
      policyOids: _getCertificatePolicyOids(),
      otherNames: otherNames,
    );
  }

  /// Convenience getter for ICP-Brasil fields.
  IcpBrasilInfo get icpBrasilInfo => extractIcpBrasilInfo();

  /// OCSP URLs from Authority Information Access (AIA).
  List<String> get ocspUrls => _getOcspUrlsFromAia();

  /// CRL distribution point URLs from CRL Distribution Points extension.
  List<String> get crlDistributionPointUrls => _getCrlDistributionPointUrls();

  static const String _oidSubjectAltName = '2.5.29.17';
  static const String _oidCertificatePolicies = '2.5.29.32';
  static const String _oidAuthorityInfoAccess = '1.3.6.1.5.5.7.1.1';
  static const String _oidOcspAccessMethod = '1.3.6.1.5.5.7.48.1';
  static const String _oidCrlDistributionPoints = '2.5.29.31';
  static const int _genUri = 6;
  static const int _distPointTypeFullName = 0;

  String? _extractDnValue(String dn, String key) {
    if (dn.isEmpty) return null;
    final pattern = RegExp('(?:^|[,/])\\s*${RegExp.escape(key)}=([^,/]+)');
    final match = pattern.firstMatch(dn);
    return match?.group(1)?.trim();
  }

  Map<String, String> _getSubjectAltNameOtherNames() {
    final nid = _objTxtToNid(_oidSubjectAltName);
    if (nid == 0) return const {};

    final namesPtr =
        _context.bindings.X509_get_ext_d2i(handle, nid, nullptr, nullptr);
    if (namesPtr == nullptr) return const {};

    final names = namesPtr.cast<GENERAL_NAMES>();
    final result = <String, String>{};

    try {
      final count = _context.bindings.OPENSSL_sk_num(names.cast());
      for (var i = 0; i < count; i++) {
        final value = _context.bindings.OPENSSL_sk_value(names.cast(), i);
        if (value == nullptr) continue;

        final generalName = value.cast<GENERAL_NAME>();
        if (generalName.ref.type != GEN_OTHERNAME) continue;

        final otherName = generalName.ref.d.otherName;
        if (otherName == nullptr) continue;

        final oid = _objToOid(otherName.ref.type_id);
        if (oid.isEmpty) continue;

        final valueString = _asn1TypeToString(otherName.ref.value);
        if (valueString == null) continue;

        result[oid] = valueString;
      }
    } finally {
      _context.bindings.GENERAL_NAMES_free(names);
    }

    return result;
  }

  List<String> _getOcspUrlsFromAia() {
    final nid = _objTxtToNid(_oidAuthorityInfoAccess);
    if (nid == 0) return const [];

    final aiaPtr =
        _context.bindings.X509_get_ext_d2i(handle, nid, nullptr, nullptr);
    if (aiaPtr == nullptr) return const [];

    final aia = aiaPtr.cast<AUTHORITY_INFO_ACCESS>();
    final result = <String>[];

    try {
      final count = _context.bindings.OPENSSL_sk_num(aia.cast());
      for (var i = 0; i < count; i++) {
        final value = _context.bindings.OPENSSL_sk_value(aia.cast(), i);
        if (value == nullptr) continue;

        final accessDescription = value.cast<ACCESS_DESCRIPTION>();
        final methodOid = _objToOid(accessDescription.ref.method);
        if (methodOid != _oidOcspAccessMethod) continue;

        final location = accessDescription.ref.location;
        if (location == nullptr || location.ref.type != _genUri) continue;

        final uri = _asn1StringToString(
          location.ref.d.uniformResourceIdentifier.cast<ASN1_STRING>(),
        );
        if (uri != null && uri.isNotEmpty) {
          result.add(uri);
        }
      }
    } finally {
      final freePtr = _context
          .lookup<Void Function(Pointer<ACCESS_DESCRIPTION>)>(
              'ACCESS_DESCRIPTION_free')
          .cast<NativeFunction<Void Function(Pointer<Void>)>>();
      _context.bindings.OPENSSL_sk_pop_free(aia.cast(), freePtr);
    }

    return result;
  }

  List<String> _getCrlDistributionPointUrls() {
    final nid = _objTxtToNid(_oidCrlDistributionPoints);
    if (nid == 0) return const [];

    final cdpPtr =
        _context.bindings.X509_get_ext_d2i(handle, nid, nullptr, nullptr);
    if (cdpPtr == nullptr) return const [];

    final cdp = cdpPtr.cast<CRL_DIST_POINTS>();
    final result = <String>[];

    try {
      final count = _context.bindings.OPENSSL_sk_num(cdp.cast());
      for (var i = 0; i < count; i++) {
        final value = _context.bindings.OPENSSL_sk_value(cdp.cast(), i);
        if (value == nullptr) continue;

        final distPoint = value.cast<DIST_POINT>();
        final distPointName = distPoint.ref.distpoint;
        if (distPointName == nullptr) continue;
        if (distPointName.ref.type != _distPointTypeFullName) continue;

        final fullNames = distPointName.ref.name.fullname;
        if (fullNames == nullptr) continue;

        final namesCount = _context.bindings.OPENSSL_sk_num(fullNames.cast());
        for (var j = 0; j < namesCount; j++) {
          final gnValue =
              _context.bindings.OPENSSL_sk_value(fullNames.cast(), j);
          if (gnValue == nullptr) continue;

          final generalName = gnValue.cast<GENERAL_NAME>();
          if (generalName.ref.type != _genUri) continue;

          final uri = _asn1StringToString(
            generalName.ref.d.uniformResourceIdentifier.cast<ASN1_STRING>(),
          );
          if (uri != null && uri.isNotEmpty) {
            result.add(uri);
          }
        }
      }
    } finally {
      final freePtr = _context
          .lookup<Void Function(Pointer<DIST_POINT>)>('DIST_POINT_free')
          .cast<NativeFunction<Void Function(Pointer<Void>)>>();
      _context.bindings.OPENSSL_sk_pop_free(cdp.cast(), freePtr);
    }

    return result;
  }

  List<String> _getCertificatePolicyOids() {
    final nid = _objTxtToNid(_oidCertificatePolicies);
    if (nid == 0) return const [];

    final policiesPtr =
        _context.bindings.X509_get_ext_d2i(handle, nid, nullptr, nullptr);
    if (policiesPtr == nullptr) return const [];

    final policies = policiesPtr.cast<CERTIFICATEPOLICIES>();
    final result = <String>[];

    try {
      final count = _context.bindings.OPENSSL_sk_num(policies.cast());
      for (var i = 0; i < count; i++) {
        final value = _context.bindings.OPENSSL_sk_value(policies.cast(), i);
        if (value == nullptr) continue;

        final policyInfo = value.cast<POLICYINFO>();
        final oid = _objToOid(policyInfo.ref.policyid);
        if (oid.isNotEmpty) result.add(oid);
      }
    } finally {
      final freePtr = _context
          .lookup<Void Function(Pointer<POLICYINFO>)>('POLICYINFO_free')
          .cast<NativeFunction<Void Function(Pointer<Void>)>>();
      _context.bindings.OPENSSL_sk_pop_free(policies.cast(), freePtr);
    }

    return result;
  }

  int _objTxtToNid(String oid) {
    final oidPtr = oid.toNativeUtf8(allocator: calloc).cast<Char>();
    try {
      return _context.bindings.OBJ_txt2nid(oidPtr);
    } finally {
      calloc.free(oidPtr);
    }
  }

  String _objToOid(Pointer<ASN1_OBJECT> obj) {
    if (obj == nullptr) return '';

    var bufferSize = 128;
    Pointer<Char> buffer = calloc<Char>(bufferSize);
    try {
      var len = _context.bindings.OBJ_obj2txt(buffer, bufferSize, obj, 1);
      if (len < 0) return '';

      if (len >= bufferSize) {
        calloc.free(buffer);
        bufferSize = len + 1;
        buffer = calloc<Char>(bufferSize);
        len = _context.bindings.OBJ_obj2txt(buffer, bufferSize, obj, 1);
        if (len < 0) return '';
      }

      return buffer.cast<Utf8>().toDartString();
    } finally {
      calloc.free(buffer);
    }
  }

  String? _asn1TypeToString(Pointer<ASN1_TYPE> value) {
    if (value == nullptr) return null;

    switch (value.ref.type) {
      case V_ASN1_OCTET_STRING:
        return _asn1StringToString(value.ref.value.octet_string);
      case V_ASN1_UTF8STRING:
        return _asn1StringToString(value.ref.value.utf8string);
      case V_ASN1_IA5STRING:
        return _asn1StringToString(value.ref.value.ia5string);
      case V_ASN1_PRINTABLESTRING:
        return _asn1StringToString(value.ref.value.printablestring);
      case V_ASN1_GENERALSTRING:
        return _asn1StringToString(value.ref.value.generalstring);
      case V_ASN1_BMPSTRING:
        return _asn1StringToString(value.ref.value.bmpstring, isBmp: true);
      case V_ASN1_OBJECT:
        return _objToOid(value.ref.value.object);
      default:
        return null;
    }
  }

  String? _asn1StringToString(
    Pointer<ASN1_STRING> stringPtr, {
    bool isBmp = false,
  }) {
    if (stringPtr == nullptr) return null;

    final length = _context.bindings.ASN1_STRING_length(stringPtr);
    if (length <= 0) return null;

    final data = _context.bindings.ASN1_STRING_get0_data(stringPtr);
    if (data == nullptr) return null;

    final bytes = Uint8List.fromList(data.cast<Uint8>().asTypedList(length));
    if (isBmp) {
      return _decodeBmpString(bytes);
    }

    try {
      return utf8.decode(bytes, allowMalformed: true).trim();
    } catch (_) {
      return _bytesToHex(bytes);
    }
  }

  String _decodeBmpString(Uint8List bytes) {
    if (bytes.length < 2) return '';
    final codeUnits = <int>[];
    for (var i = 0; i + 1 < bytes.length; i += 2) {
      final codeUnit = (bytes[i] << 8) | bytes[i + 1];
      codeUnits.add(codeUnit);
    }
    return String.fromCharCodes(codeUnits).trim();
  }

  String _bytesToHex(Uint8List bytes) => encodeHex(bytes);
}
