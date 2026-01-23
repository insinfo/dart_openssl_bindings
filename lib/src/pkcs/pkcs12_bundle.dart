import '../crypto/evp_pkey.dart';
import '../x509/x509_certificate.dart';

/// Represents parsed PKCS#12/PFX data.
class Pkcs12Bundle {
  final EvpPkey privateKey;
  final X509Certificate certificate;
  final List<X509Certificate> caCertificates;

  const Pkcs12Bundle({
    required this.privateKey,
    required this.certificate,
    required this.caCertificates,
  });
}
