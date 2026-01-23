/// Helper types for X.509 extension builders.
class X509OtherName {
  final String oid;
  final String value;

  const X509OtherName(this.oid, this.value);
}
