# Tutorial: Certificados com Serial Longo (BigInt)

Este guia mostra como gerar certificados X.509 com serial longo (ex.: 128 bits), no padrao esperado para PKI/ICP, usando `openssl_bindings`.

## Pre-requisitos

- Dart SDK instalado
- Dependencia `openssl_bindings` no `pubspec.yaml`
- OpenSSL disponivel no sistema (ou caminhos configurados via variaveis de ambiente)

## 1. Gerar serial longo (128 bits)

Use o helper da biblioteca para gerar serial criptograficamente forte:

```dart
final openssl = OpenSSL();
final serial128 = openssl.generateSerialNumberBigInt(bytes: 16); // 16 bytes = 128 bits
```

Faixa recomendada pelo proprio helper:

- `8` a `20` bytes (64 a 160 bits)

## 2. Criar certificado com serial BigInt

Exemplo de certificado autoassinado:

```dart
import 'package:openssl_bindings/openssl.dart';

void main() {
  final openssl = OpenSSL();

  final caKey = openssl.generateRsa(2048);
  final serial128 = openssl.generateSerialNumberBigInt(bytes: 16);

  final cert = X509CertificateBuilder(openssl)
    ..setSubject(
      commonName: 'Minha CA',
      organization: 'Minha Organizacao',
      country: 'BR',
    )
    ..setIssuerAsSubject()
    ..setPublicKey(caKey)
    ..setSerialNumberBigInt(serial128)
    ..setValidity(notBeforeOffset: 0, notAfterOffset: 365 * 24 * 3600)
    ..addBasicConstraints(isCa: true, critical: true)
    ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true)
    .sign(caKey);

  print('Serial decimal: ${cert.serialNumber}');
  print(cert.toPem());
}
```

## 3. Assinar certificado de usuario com serial longo

```dart
final openssl = OpenSSL();

final caKey = openssl.generateRsa(2048);
final caCert = X509CertificateBuilder(openssl)
  ..setSubject(commonName: 'AC Raiz', organization: 'Exemplo', country: 'BR')
  ..setIssuerAsSubject()
  ..setPublicKey(caKey)
  ..setSerialNumberBigInt(openssl.generateSerialNumberBigInt(bytes: 16))
  ..setValidity(notAfterOffset: 365 * 24 * 3600)
  ..addBasicConstraints(isCa: true, critical: true)
  ..addKeyUsage(keyCertSign: true, cRLSign: true, critical: true);
final issuerCert = caCert.sign(caKey);

final userKey = openssl.generateRsa(2048);
final userSerial = openssl.generateSerialNumberBigInt(bytes: 16);

final userCert = X509CertificateBuilder(openssl)
  ..setSubject(commonName: 'Usuario Final', organization: 'Cliente', country: 'BR')
  ..setIssuer(issuerCert: issuerCert)
  ..setPublicKey(userKey)
  ..setSerialNumberBigInt(userSerial)
  ..setValidity(notAfterOffset: 180 * 24 * 3600)
  ..addBasicConstraints(isCa: false, critical: true)
  ..addKeyUsage(digitalSignature: true, keyEncipherment: true, critical: true)
  .sign(caKey);

print('Serial usuario (decimal): ${userCert.serialNumber}');
```

## Boas praticas

- Nao reutilize serial entre certificados.
- Use fonte forte de aleatoriedade (`generateSerialNumberBigInt`).
- Evite serial `0` ou negativo.
- Para auditoria, persista serial em decimal e/ou hexadecimal no seu banco.

## Observacoes

- `setSerialNumber(int)` continua disponivel, mas e limitado ao caminho baseado em inteiro nativo.
- Para serial longo, prefira sempre `setSerialNumberBigInt(BigInt)`.
