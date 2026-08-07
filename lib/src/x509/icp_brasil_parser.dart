/// Extraction of the Brazilian ICP-Brasil identifiers from a certificate.
///
/// The value of the natural-person `otherName` (OID `2.16.76.1.3.1`) is **not**
/// a CPF: it is a positional block defined by DOC-ICP-04.
///
/// ```
/// 25101982 | 09498269793 | 00000000000 | 000000000000000 | SSPDF
/// --------   -----------   -----------   ---------------   -----
/// birthdate  CPF           NIS/PIS       ID card number    issuer
/// (DDMMYYYY) (11 digits)   (11 digits)   (15 digits)       (6 chars)
/// ```
///
/// The CPF sits at `[8, 19)`. Two tempting approaches are wrong:
///
/// - `substring(0, 11)` yields `25101982094` (birth date + 3 CPF digits);
/// - "first 11-digit window with valid check digits" is ambiguous — a block can
///   hold several windows that pass the check-digit maths, and a birth date can
///   itself start a valid one. Only the official offset is trustworthy.
///
/// The order recommended by the standard is to look first at the `serialNumber`
/// attribute of the Subject DN (OID `2.5.4.5`), which carries the CPF/CNPJ
/// directly and is the current form; the positional block is compatibility,
/// kept until 2028-12-31.
abstract final class IcpBrasilParser {
  /// Natural-person `otherName`: positional block with birth date, CPF, NIS
  /// and ID card.
  static const String oidNaturalPerson = '2.16.76.1.3.1';

  /// `otherName` with the name of the person responsible for a legal entity.
  static const String oidLegalEntityResponsibleName = '2.16.76.1.3.2';

  /// `otherName` carrying the CNPJ of a legal entity.
  static const String oidCnpj = '2.16.76.1.3.3';

  /// `otherName` of the person responsible for a legal entity: same positional
  /// layout as [oidNaturalPerson].
  static const String oidLegalEntityResponsible = '2.16.76.1.3.4';

  /// `otherName` with the voter registration (título de eleitor) of a natural
  /// person: 12 digits + 3 (zone) + 4 (section) + 22 (city/state).
  static const String oidVoterRegistration = '2.16.76.1.3.5';

  /// `otherName` with the INSS-specific registration (CEI) of a natural
  /// person — 12 digits.
  ///
  /// Note this is **not** a birth date, despite being read as one by earlier
  /// versions of this package; the birth date lives in the first 8 digits of
  /// [oidNaturalPerson].
  static const String oidNaturalPersonCei = '2.16.76.1.3.6';

  /// `otherName` with the INSS-specific registration (CEI) of a legal entity.
  static const String oidLegalEntityCei = '2.16.76.1.3.7';

  /// `otherName` with the business name of a legal entity.
  static const String oidCompanyName = '2.16.76.1.3.8';

  /// `serialNumber` attribute of the Subject DN. For a natural person it holds
  /// the CPF; for a legal entity, the CNPJ.
  ///
  /// Not to be confused with the X.509 serial number
  /// (`X509Certificate.serialNumber`), which the CA assigns to the certificate.
  static const String oidDnSerialNumber = '2.5.4.5';

  // Field offsets inside the natural-person block.
  static const int _birthDateEnd = 8;
  static const int _cpfStart = 8;
  static const int _cpfEnd = 19;
  static const int _nisStart = 19;
  static const int _nisEnd = 30;
  static const int _idCardStart = 30;
  static const int _idCardEnd = 45;

  /// Extracts the CPF in the order recommended by the standard:
  ///
  /// 1. `serialNumber` of the Subject DN (CPF directly);
  /// 2. natural-person `otherName` (positional block);
  /// 3. `otherName` of the legal entity's responsible (same block layout).
  ///
  /// Returns 11 digits with verified check digits, or `null`.
  static String? extractCpf({
    String? subjectDn,
    String? otherNameNaturalPerson,
    String? otherNameResponsible,
  }) {
    final fromDn = _digitsOnly(_dnAttribute(subjectDn, 'serialNumber') ??
        _dnAttribute(subjectDn, oidDnSerialNumber));
    if (fromDn != null && fromDn.length == 11 && isValidCpf(fromDn)) {
      return fromDn;
    }

    for (final block in [otherNameNaturalPerson, otherNameResponsible]) {
      final cpf = extractCpfFromBlock(block);
      if (cpf != null) return cpf;
    }
    return null;
  }

  /// Extracts the CPF from a natural-person positional block.
  ///
  /// A value that is already an isolated CPF is accepted as well.
  static String? extractCpfFromBlock(String? value) {
    final digits = _digitsOnly(value);
    if (digits == null) return null;

    if (digits.length == 11) {
      return isValidCpf(digits) ? digits : null;
    }
    if (digits.length >= _cpfEnd) {
      final cpf = digits.substring(_cpfStart, _cpfEnd);
      return isValidCpf(cpf) ? cpf : null;
    }
    return null;
  }

  /// Extracts the CNPJ (14 digits) from the DN `serialNumber` or from the
  /// [oidCnpj] `otherName`. Returns `null` when absent or when the check digits
  /// do not match.
  static String? extractCnpj({
    String? subjectDn,
    String? otherNameCnpj,
  }) {
    final fromOtherName = _digitsOnly(otherNameCnpj);
    if (fromOtherName != null &&
        fromOtherName.length == 14 &&
        isValidCnpj(fromOtherName)) {
      return fromOtherName;
    }

    final fromDn = _digitsOnly(_dnAttribute(subjectDn, 'serialNumber') ??
        _dnAttribute(subjectDn, oidDnSerialNumber));
    if (fromDn != null && fromDn.length == 14 && isValidCnpj(fromDn)) {
      return fromDn;
    }
    return null;
  }

  /// Birth date stored in the first 8 digits (DDMMYYYY) of the natural-person
  /// block, or `null` when missing or invalid.
  static DateTime? extractBirthDate(String? naturalPersonBlock) {
    final digits = _digitsOnly(naturalPersonBlock);
    if (digits == null || digits.length < _birthDateEnd) return null;

    final day = int.tryParse(digits.substring(0, 2));
    final month = int.tryParse(digits.substring(2, 4));
    final year = int.tryParse(digits.substring(4, 8));
    if (day == null || month == null || year == null) return null;
    if (day < 1 || day > 31 || month < 1 || month > 12 || year < 1900) {
      return null;
    }

    final date = DateTime.utc(year, month, day);
    // Rejects dates such as 31/02, which DateTime would roll over into March.
    if (date.day != day || date.month != month) return null;
    return date;
  }

  /// NIS/PIS/PASEP stored at `[19, 30)` of the natural-person block.
  ///
  /// Returns `null` when the field is absent or filled with zeroes, which is
  /// how CAs mark "not informed".
  static String? extractNis(String? naturalPersonBlock) =>
      _fieldOrNull(naturalPersonBlock, _nisStart, _nisEnd);

  /// ID card number (RG) stored at `[30, 45)` of the natural-person block.
  ///
  /// Returns `null` when absent or filled with zeroes. Leading zeroes used as
  /// padding are stripped; the issuing body that follows the number is not
  /// numeric and is not returned here — read it from the raw `otherName` when
  /// needed.
  static String? extractIdCard(String? naturalPersonBlock) {
    final field = _fieldOrNull(naturalPersonBlock, _idCardStart, _idCardEnd);
    if (field == null) return null;
    final trimmed = field.replaceFirst(RegExp(r'^0+'), '');
    return trimmed.isEmpty ? null : trimmed;
  }

  /// Masks a CPF for logging, keeping only the middle digits
  /// (`***.456.789-**`), as expected by the Brazilian data protection law.
  ///
  /// Returns an empty string when [cpf] does not hold 11 digits, so a malformed
  /// value never leaks in full through a log line.
  static String maskCpf(String? cpf) {
    final digits = _digitsOnly(cpf);
    if (digits == null || digits.length != 11) return '';
    return '***.${digits.substring(3, 6)}.${digits.substring(6, 9)}-**';
  }

  /// Masks a CNPJ for logging (`**.345.678/0001-**`).
  ///
  /// Returns an empty string when [cnpj] does not hold 14 digits.
  static String maskCnpj(String? cnpj) {
    final digits = _digitsOnly(cnpj);
    if (digits == null || digits.length != 14) return '';
    return '**.${digits.substring(2, 5)}.${digits.substring(5, 8)}'
        '/${digits.substring(8, 12)}-**';
  }

  /// Validates the check digits of an 11-digit CPF.
  static bool isValidCpf(String cpf) {
    if (cpf.length != 11) return false;
    if (RegExp(r'^(\d)\1{10}$').hasMatch(cpf)) return false;

    int checkDigit(int count) {
      var sum = 0;
      var weight = count + 1;
      for (var i = 0; i < count; i++) {
        sum += int.parse(cpf[i]) * weight--;
      }
      final rest = sum % 11;
      return rest < 2 ? 0 : 11 - rest;
    }

    return checkDigit(9) == int.parse(cpf[9]) &&
        checkDigit(10) == int.parse(cpf[10]);
  }

  /// Validates the check digits of a 14-digit CNPJ.
  static bool isValidCnpj(String cnpj) {
    if (cnpj.length != 14) return false;
    if (RegExp(r'^(\d)\1{13}$').hasMatch(cnpj)) return false;

    int checkDigit(List<int> weights) {
      var sum = 0;
      for (var i = 0; i < weights.length; i++) {
        sum += int.parse(cnpj[i]) * weights[i];
      }
      final rest = sum % 11;
      return rest < 2 ? 0 : 11 - rest;
    }

    const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    return checkDigit(weights1) == int.parse(cnpj[12]) &&
        checkDigit(weights2) == int.parse(cnpj[13]);
  }

  /// Value of a DN attribute in `key=value` form, comma separated. The key
  /// match is case-insensitive.
  static String? _dnAttribute(String? dn, String key) {
    if (dn == null || dn.isEmpty) return null;
    final re = RegExp(
      '(?:^|,)\\s*${RegExp.escape(key)}=([^,]+)',
      caseSensitive: false,
    );
    return re.firstMatch(dn)?.group(1)?.trim();
  }

  /// A positional field of the natural-person block, or `null` when the block
  /// is too short or the field is all zeroes.
  static String? _fieldOrNull(String? block, int start, int end) {
    final digits = _digitsOnly(block);
    if (digits == null || digits.length < end) return null;
    final field = digits.substring(start, end);
    return RegExp(r'^0+$').hasMatch(field) ? null : field;
  }

  static String? _digitsOnly(String? value) {
    if (value == null) return null;
    final digits = value.replaceAll(RegExp(r'\D'), '');
    return digits.isEmpty ? null : digits;
  }
}
