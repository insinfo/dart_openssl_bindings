/// Parsed ICP-Brasil fields extracted from a certificate.
class IcpBrasilInfo {
  /// Subject name (usually CommonName).
  final String? name;

  /// CPF, 11 digits, already cut from the official offset of the ICP-Brasil
  /// block and with its check digits verified.
  ///
  /// **Changed in 1.0.0**: up to 0.6.0 this field returned the raw positional
  /// block of OID 2.16.76.1.3.1 (birth date + CPF + NIS + ID card), which made
  /// `cpf.substring(0, 11)` yield a wrong number. The raw value is still
  /// available in [cpfOtherNameRaw].
  final String? cpf;

  /// Raw value of the natural-person `otherName` (OID 2.16.76.1.3.1), exactly
  /// as it came in the certificate.
  final String? cpfOtherNameRaw;

  /// CNPJ, 14 digits (OID 2.16.76.1.3.3 or the DN `serialNumber`), with its
  /// check digits verified.
  final String? cnpj;

  /// Birth date, read from the first 8 digits (DDMMYYYY) of the
  /// natural-person block.
  ///
  /// **Changed in 1.0.0**: this used to be read from OID 2.16.76.1.3.6, which
  /// DOC-ICP-04 defines as the INSS registration (CEI), not a date — see
  /// [cei].
  final DateTime? birthDate;

  /// NIS/PIS/PASEP from the natural-person block, or `null` when the CA left
  /// the field zeroed.
  final String? nis;

  /// ID card number (RG) from the natural-person block, without the padding
  /// zeroes, or `null` when not informed.
  final String? idCard;

  /// INSS-specific registration (CEI) of the holder, natural person
  /// (OID 2.16.76.1.3.6) or legal entity (OID 2.16.76.1.3.7).
  final String? cei;

  /// Voter registration (título de eleitor), OID 2.16.76.1.3.5.
  final String? voterRegistration;

  /// Business name of the legal entity (OID 2.16.76.1.3.8).
  final String? companyName;

  /// Name of the person responsible for the legal entity
  /// (OID 2.16.76.1.3.2).
  final String? responsibleName;

  /// Policy OIDs from the Certificate Policies extension.
  final List<String> policyOids;

  /// Raw otherName values keyed by OID.
  final Map<String, String> otherNames;

  const IcpBrasilInfo({
    this.name,
    this.cpf,
    this.cpfOtherNameRaw,
    this.cnpj,
    this.birthDate,
    this.nis,
    this.idCard,
    this.cei,
    this.voterRegistration,
    this.companyName,
    this.responsibleName,
    this.policyOids = const [],
    this.otherNames = const {},
  });

  /// Whether the certificate identifies a legal entity (it carries a CNPJ).
  bool get isLegalEntity => cnpj != null;

  @override
  String toString() => 'IcpBrasilInfo(name: $name, '
      'cpf: ${cpf == null ? null : '***'}, '
      'cnpj: ${cnpj == null ? null : '***'})';
}
