import 'dart:typed_data';
import '../api/openssl_context.dart';
import '../crypto/evp_pkey.dart';
import '../x509/x509_builder.dart';
import '../x509/x509_certificate.dart';

/// High-level PKI helper for certificate issuance.
mixin PkiBuilderMixin on OpenSslContext {
  /// Output of a CA rollover cross-certificate operation.
  ///
  /// [oldSignedByNew] is the old CA subject signed by the new CA.
  /// [newSignedByOld] is the new CA subject signed by the old CA.
  static const int _defaultCaValiditySeconds = 31536000;

  /// Creates a cross certificate for CA rollover.
  Uint8List createCrossCertificate({
    required X509Certificate subjectCert,
    required EvpPkey subjectKeyPair,
    required X509Certificate issuerCert,
    required EvpPkey issuerKeyPair,
    int? serialNumber,
    BigInt? serialNumberBigInt,
    int notBeforeOffset = 0,
    int notAfterOffset = _defaultCaValiditySeconds,
    int? pathLen,
    bool basicConstraintsCritical = true,
    bool keyUsageKeyCertSign = true,
    bool keyUsageCrlSign = true,
    bool keyUsageCritical = true,
    String hashAlgorithm = 'SHA256',
  }) {
    final builder = X509CertificateBuilder(this as dynamic);

    if (serialNumberBigInt != null) {
      builder.setSerialNumberBigInt(serialNumberBigInt);
    } else if (serialNumber != null) {
      builder.setSerialNumber(serialNumber);
    } else {
      builder.setSerialNumberBigInt((this as dynamic).generateSerialNumberBigInt());
    }

    final subjectDn = subjectCert.subject;
    final issuerDn = issuerCert.subject;
    if (subjectDn.isEmpty || issuerDn.isEmpty) {
      throw StateError('Subject or issuer DN is empty for cross certificate');
    }

    _applyDn(builder, subjectDn, isIssuer: false);
    _applyDn(builder, issuerDn, isIssuer: true);

    builder.setPublicKey(subjectKeyPair);
    builder.setValidity(
      notBeforeOffset: notBeforeOffset,
      notAfterOffset: notAfterOffset,
    );

    builder.addBasicConstraints(
      isCa: true,
      pathLen: pathLen,
      critical: basicConstraintsCritical,
    );

    builder.addKeyUsage(
      keyCertSign: keyUsageKeyCertSign,
      cRLSign: keyUsageCrlSign,
      critical: keyUsageCritical,
    );

    final cert = builder.sign(issuerKeyPair, hashAlgorithm: hashAlgorithm);
    return cert.toDer();
  }

  /// Creates the pair of cross certificates used during CA rollover.
  RolloverChain createRolloverCrossCertificates({
    required X509Certificate oldCaCert,
    required EvpPkey oldCaKey,
    required X509Certificate newCaCert,
    required EvpPkey newCaKey,
    BigInt? oldSignedByNewSerial,
    BigInt? newSignedByOldSerial,
    int notBeforeOffset = 0,
    int notAfterOffset = _defaultCaValiditySeconds,
    int? pathLen,
    bool basicConstraintsCritical = true,
    bool keyUsageKeyCertSign = true,
    bool keyUsageCrlSign = true,
    bool keyUsageCritical = true,
    String hashAlgorithm = 'SHA256',
  }) {
    final oldSignedByNew = createCrossCertificate(
      subjectCert: oldCaCert,
      subjectKeyPair: oldCaKey,
      issuerCert: newCaCert,
      issuerKeyPair: newCaKey,
      serialNumberBigInt: oldSignedByNewSerial,
      notBeforeOffset: notBeforeOffset,
      notAfterOffset: notAfterOffset,
      pathLen: pathLen,
      basicConstraintsCritical: basicConstraintsCritical,
      keyUsageKeyCertSign: keyUsageKeyCertSign,
      keyUsageCrlSign: keyUsageCrlSign,
      keyUsageCritical: keyUsageCritical,
      hashAlgorithm: hashAlgorithm,
    );

    final newSignedByOld = createCrossCertificate(
      subjectCert: newCaCert,
      subjectKeyPair: newCaKey,
      issuerCert: oldCaCert,
      issuerKeyPair: oldCaKey,
      serialNumberBigInt: newSignedByOldSerial,
      notBeforeOffset: notBeforeOffset,
      notAfterOffset: notAfterOffset,
      pathLen: pathLen,
      basicConstraintsCritical: basicConstraintsCritical,
      keyUsageKeyCertSign: keyUsageKeyCertSign,
      keyUsageCrlSign: keyUsageCrlSign,
      keyUsageCritical: keyUsageCritical,
      hashAlgorithm: hashAlgorithm,
    );

    return RolloverChain(
      oldSignedByNew: oldSignedByNew,
      newSignedByOld: newSignedByOld,
    );
  }
  /// Creates a user certificate and returns DER bytes.
  Uint8List createUserCertificate({
    required EvpPkey keyPair,
    required EvpPkey issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    int? serialNumber,
    BigInt? serialNumberBigInt,
    int notBeforeOffset = 0,
    int notAfterOffset = 31536000,
    bool isCa = false,
    int? pathLen,
    bool basicConstraintsCritical = true,
    bool keyUsageDigitalSignature = true,
    bool keyUsageNonRepudiation = false,
    bool keyUsageKeyEncipherment = true,
    bool keyUsageDataEncipherment = false,
    bool keyUsageKeyAgreement = false,
    bool keyUsageKeyCertSign = false,
    bool keyUsageCrlSign = false,
    bool keyUsageEncipherOnly = false,
    bool keyUsageDecipherOnly = false,
    bool keyUsageCritical = true,
    List<String> extendedKeyUsageOids = const [],
    String hashAlgorithm = 'SHA256',
  }) {
    final builder = X509CertificateBuilder(this as dynamic);

    if (serialNumberBigInt != null) {
      builder.setSerialNumberBigInt(serialNumberBigInt);
    } else if (serialNumber != null) {
      builder.setSerialNumber(serialNumber);
    } else {
      builder.setSerialNumberBigInt((this as dynamic).generateSerialNumberBigInt());
    }

    _applyDn(builder, subjectDn, isIssuer: false);
    _applyDn(builder, issuerDn, isIssuer: true);

    builder.setPublicKey(keyPair);
    builder.setValidity(
      notBeforeOffset: notBeforeOffset,
      notAfterOffset: notAfterOffset,
    );

    builder.addBasicConstraints(
      isCa: isCa,
      pathLen: pathLen,
      critical: basicConstraintsCritical,
    );

    builder.addKeyUsage(
      digitalSignature: keyUsageDigitalSignature,
      nonRepudiation: keyUsageNonRepudiation,
      keyEncipherment: keyUsageKeyEncipherment,
      dataEncipherment: keyUsageDataEncipherment,
      keyAgreement: keyUsageKeyAgreement,
      keyCertSign: keyUsageKeyCertSign,
      cRLSign: keyUsageCrlSign,
      encipherOnly: keyUsageEncipherOnly,
      decipherOnly: keyUsageDecipherOnly,
      critical: keyUsageCritical,
    );

    if (extendedKeyUsageOids.isNotEmpty) {
      builder.addExtendedKeyUsage(extendedKeyUsageOids);
    }

    final cert = builder.sign(issuerKeyPair, hashAlgorithm: hashAlgorithm);
    return cert.toDer();
  }

  void _applyDn(X509CertificateBuilder builder, String dn, {required bool isIssuer}) {
    final entries = _parseDn(dn);
    for (final entry in entries) {
      final field = _mapDnField(entry.key);
      if (isIssuer) {
        builder.addIssuerEntry(field, entry.value);
      } else {
        builder.addSubjectEntry(field, entry.value);
      }
    }
  }

  List<MapEntry<String, String>> _parseDn(String dn) {
    final parts = dn.split(',');
    final entries = <MapEntry<String, String>>[];
    for (final raw in parts) {
      final part = raw.trim();
      if (part.isEmpty) continue;
      final idx = part.indexOf('=');
      if (idx <= 0) continue;
      final key = part.substring(0, idx).trim();
      final value = part.substring(idx + 1).trim();
      if (key.isEmpty || value.isEmpty) continue;
      entries.add(MapEntry(key, value));
    }
    return entries;
  }

  String _mapDnField(String key) {
    final upper = key.toUpperCase();
    switch (upper) {
      case 'E':
      case 'EMAIL':
      case 'EMAILADDRESS':
        return 'emailAddress';
      case 'SERIALNUMBER':
        return 'serialNumber';
      default:
        return upper;
    }
  }
}

class RolloverChain {
  final Uint8List oldSignedByNew;
  final Uint8List newSignedByOld;

  const RolloverChain({
    required this.oldSignedByNew,
    required this.newSignedByOld,
  });
}
