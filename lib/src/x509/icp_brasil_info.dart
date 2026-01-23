/// Parsed ICP-Brasil fields extracted from a certificate.
class IcpBrasilInfo {
  /// Subject name (usually CommonName).
  final String? name;

  /// CPF identifier (OID 2.16.76.1.3.1) if present in SubjectAltName otherName.
  final String? cpf;

  /// Birth date (OID 2.16.76.1.3.6) if present in SubjectAltName otherName.
  final DateTime? birthDate;

  /// Policy OIDs from Certificate Policies extension.
  final List<String> policyOids;

  /// Raw otherName values keyed by OID.
  final Map<String, String> otherNames;

  const IcpBrasilInfo({
    this.name,
    this.cpf,
    this.birthDate,
    this.policyOids = const [],
    this.otherNames = const {},
  });
}
