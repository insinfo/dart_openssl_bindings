import 'dart:convert';
import 'dart:typed_data';

import 'block_ciphers.dart';
import 'der.dart';
import 'digests.dart';

/// PKCS#12 bundle decoded in pure Dart (no FFI, no OpenSSL).
///
/// It exists because of files encrypted with algorithms that OpenSSL 3.x
/// moved to the `legacy` provider — chiefly `pbeWithSHA1And40BitRC2-CBC`,
/// used by several CAs, including Tramita.GOV.BR's. Where the `legacy`
/// module is not installed (containers, slim servers), this path still
/// works.
///
/// ```dart
/// final bundle = decodePkcs12Pure(bytes, password: 'secret');
/// print(bundle.certificatePem);
/// ```
///
/// Supported decryption algorithms:
///
/// | OID                        | Algoritmo                          |
/// |----------------------------|------------------------------------|
/// | 1.2.840.113549.1.12.1.1    | pbeWithSHA1And128BitRC4            |
/// | 1.2.840.113549.1.12.1.2    | pbeWithSHA1And40BitRC4             |
/// | 1.2.840.113549.1.12.1.3    | pbeWithSHA1And3-KeyTripleDES-CBC   |
/// | 1.2.840.113549.1.12.1.4    | pbeWithSHA1And2-KeyTripleDES-CBC   |
/// | 1.2.840.113549.1.12.1.5    | pbeWithSHA1And128BitRC2-CBC        |
/// | 1.2.840.113549.1.12.1.6    | pbeWithSHA1And40BitRC2-CBC         |
/// | 1.2.840.113549.1.5.13      | PBES2 (PBKDF2 + AES-CBC / 3DES-CBC)|
class PurePkcs12Bundle {
  /// Private key in DER, as a PKCS#8 `PrivateKeyInfo`.
  final Uint8List privateKeyDer;

  /// End-entity certificate, in DER.
  final Uint8List certificateDer;

  /// Remaining certificates of the file (the chain), in DER.
  final List<Uint8List> chainDer;

  /// `friendlyName` attribute of the key bag, when present.
  final String? friendlyName;

  const PurePkcs12Bundle({
    required this.privateKeyDer,
    required this.certificateDer,
    required this.chainDer,
    this.friendlyName,
  });

  /// Private key in PEM (`-----BEGIN PRIVATE KEY-----`).
  String get privateKeyPem => _toPem('PRIVATE KEY', privateKeyDer);

  /// End-entity certificate in PEM.
  String get certificatePem => _toPem('CERTIFICATE', certificateDer);

  /// Chain in PEM, in the order it appeared in the file.
  List<String> get chainPem =>
      chainDer.map((der) => _toPem('CERTIFICATE', der)).toList();

  /// Key + certificate + chain in a single PEM, in the same shape that
  /// `openssl pkcs12 -nodes -out file.pem` produces.
  String get fullPem => [
        privateKeyPem,
        certificatePem,
        ...chainPem,
      ].join('\n');

  @override
  String toString() => 'PurePkcs12Bundle('
      'chain: ${chainDer.length}'
      '${friendlyName == null ? '' : ', friendlyName: $friendlyName'})';
}

/// Error raised by the pure PKCS#12 decoder.
class PurePkcs12Exception implements Exception {
  /// What went wrong.
  final String message;

  PurePkcs12Exception(this.message);

  @override
  String toString() => 'PurePkcs12Exception: $message';
}

/// Decodes a PKCS#12/PFX file in pure Dart.
///
/// [verifyMac] checks the file MAC before decrypting, which tells a wrong
/// password apart from a corrupted file. Turn it off only for MAC-less files
/// written by old tooling.
PurePkcs12Bundle decodePkcs12Pure(
  Uint8List bytes, {
  required String password,
  bool verifyMac = true,
}) {
  // Any encoding defect becomes a PurePkcs12Exception: callers should not
  // have to tell a DER parser FormatException apart from anything else.
  try {
    return _decode(bytes, password, verifyMac);
  } on FormatException catch (e) {
    throw PurePkcs12Exception('Not a valid PKCS#12 file: ${e.message}');
  } on RangeError catch (e) {
    throw PurePkcs12Exception('Unexpected PKCS#12 structure: ${e.message}');
  } on TypeError {
    throw PurePkcs12Exception('Unexpected PKCS#12 structure');
  }
}

PurePkcs12Bundle _decode(
  Uint8List bytes,
  String password,
  bool verifyMac,
) {
  final pfx = readDer(bytes);

  final top = pfx.elements;
  if (top.length < 2) {
    throw PurePkcs12Exception('Incomplete PKCS#12');
  }

  final authSafeInfo = top[1];
  final credentials = _Password(password);

  if (verifyMac && top.length > 2) {
    _verifyMac(top[2], _rawContent(authSafeInfo), credentials.bmp);
  }

  final authSafe = _readContentInfo(authSafeInfo, credentials);
  final keys = <_KeyBag>[];
  final certificates = <_CertBag>[];

  for (final contentInfo in readDer(authSafe).elements) {
    final content = _readContentInfo(contentInfo, credentials);
    if (content.isEmpty) continue;

    for (final bag in readDer(content).elements) {
      final parts = bag.elements;
      if (parts.length < 2) continue;

      final type = parts[0].oid;
      final attributes = parts.length > 2 ? _readAttributes(parts[2]) : null;

      switch (type) {
        case _oidKeyBag:
          keys.add(_KeyBag(_explicitContent(parts[1]), attributes));
        case _oidShroudedKeyBag:
          final decrypted = _decryptPrivateKey(
            _explicitContent(parts[1]),
            credentials,
          );
          keys.add(_KeyBag(decrypted, attributes));
        case _oidCertBag:
          final cert = _readCertBag(parts[1]);
          if (cert != null) {
            certificates.add(_CertBag(cert, attributes));
          }
      }
    }
  }

  if (keys.isEmpty) {
    throw PurePkcs12Exception('PKCS#12 has no private key');
  }
  if (certificates.isEmpty) {
    throw PurePkcs12Exception('PKCS#12 has no certificates');
  }

  final key = keys.first;
  final localKeyId = key.attributes?.localKeyId;

  // Match the end-entity certificate to the key by localKeyId when present;
  // without it, a file carrying a chain could return the CA certificate.
  var endEntityIndex = 0;
  if (localKeyId != null) {
    final matched = certificates.indexWhere(
      (c) =>
          c.attributes?.localKeyId != null &&
          constantTimeEquals(c.attributes!.localKeyId!, localKeyId),
    );
    if (matched >= 0) endEntityIndex = matched;
  }

  final endEntity = certificates[endEntityIndex];
  final chain = <Uint8List>[
    for (var i = 0; i < certificates.length; i++)
      if (i != endEntityIndex) certificates[i].der,
  ];

  return PurePkcs12Bundle(
    privateKeyDer: key.der,
    certificateDer: endEntity.der,
    chainDer: chain,
    friendlyName: key.attributes?.friendlyName ?? endEntity.attributes?.friendlyName,
  );
}

/// The password in both shapes PKCS#12 needs: a BMPString (for the PKCS#12
/// PBEs) and text (PBES2 derives the key from its UTF-8 bytes).
class _Password {
  final String text;
  final Uint8List bmp;

  _Password(this.text) : bmp = passwordToBmp(text);
}

// -----------------------------------------------------------------------------
// ContentInfo / SafeBag
// -----------------------------------------------------------------------------

/// Content bytes of a ContentInfo before any decryption — the PKCS#12 MAC is
/// computed over exactly these.
Uint8List _rawContent(DerValue contentInfo) {
  final parts = contentInfo.elements;
  if (parts.length < 2) return Uint8List(0);

  switch (parts[0].oid) {
    case _oidData:
      return _explicitContent(parts[1]);
    case _oidEncryptedData:
      final encryptedData = readDer(_explicitContent(parts[1])).elements;
      final encryptedContentInfo = encryptedData[1].elements;
      return encryptedContentInfo[2].octets;
    default:
      return Uint8List(0);
  }
}

Uint8List _readContentInfo(DerValue contentInfo, _Password password) {
  final parts = contentInfo.elements;
  if (parts.length < 2) return Uint8List(0);

  final type = parts[0].oid;
  if (type == _oidData) {
    return _explicitContent(parts[1]);
  }

  if (type == _oidEncryptedData) {
    final encryptedData = readDer(_explicitContent(parts[1])).elements;
    if (encryptedData.length < 2) {
      throw PurePkcs12Exception('Malformed EncryptedData');
    }
    final encryptedContentInfo = encryptedData[1].elements;
    if (encryptedContentInfo.length < 3) {
      throw PurePkcs12Exception('Malformed EncryptedContentInfo');
    }
    return _decrypt(
      encryptedContentInfo[1],
      encryptedContentInfo[2].octets,
      password,
    );
  }

  throw PurePkcs12Exception('Unsupported ContentInfo: $type');
}

Uint8List? _readCertBag(DerValue bagValue) {
  final certBag = readDer(_explicitContent(bagValue)).elements;
  if (certBag.length < 2) return null;
  if (certBag[0].oid != _oidX509Cert) return null;
  return Uint8List.fromList(_explicitContent(certBag[1]));
}

Uint8List _decryptPrivateKey(Uint8List encrypted, _Password password) {
  final parts = readDer(encrypted).elements;
  if (parts.length < 2) {
    throw PurePkcs12Exception('Malformed EncryptedPrivateKeyInfo');
  }
  return _decrypt(parts[0], parts[1].octets, password);
}

/// Content of a `[0] EXPLICIT` wrapper (or of a plain OCTET STRING).
Uint8List _explicitContent(DerValue valor) {
  if (valor.tag == 0x04) return valor.content;
  if (valor.constructed) {
    final filho = valor.first;
    if (filho != null) {
      return filho.tag == 0x04 ? filho.content : filho.bytes;
    }
  }
  return valor.content;
}

// -----------------------------------------------------------------------------
// Bag attributes
// -----------------------------------------------------------------------------

class _Attributes {
  final Uint8List? localKeyId;
  final String? friendlyName;

  const _Attributes(this.localKeyId, this.friendlyName);
}

_Attributes? _readAttributes(DerValue attributeSet) {
  Uint8List? localKeyId;
  String? friendlyName;

  for (final atributo in attributeSet.elements) {
    final parts = atributo.elements;
    if (parts.length < 2) continue;

    final values = parts[1].elements;
    if (values.isEmpty) continue;

    switch (parts[0].oid) {
      case _oidLocalKeyId:
        localKeyId = Uint8List.fromList(values.first.content);
      case _oidFriendlyName:
        friendlyName = _bmpToString(values.first.content);
    }
  }

  if (localKeyId == null && friendlyName == null) return null;
  return _Attributes(localKeyId, friendlyName);
}

String _bmpToString(Uint8List bytes) {
  final units = <int>[];
  for (var i = 0; i + 1 < bytes.length; i += 2) {
    units.add((bytes[i] << 8) | bytes[i + 1]);
  }
  return String.fromCharCodes(units);
}

class _KeyBag {
  final Uint8List der;
  final _Attributes? attributes;

  const _KeyBag(this.der, this.attributes);
}

class _CertBag {
  final Uint8List der;
  final _Attributes? attributes;

  const _CertBag(this.der, this.attributes);
}

// -----------------------------------------------------------------------------
// MAC
// -----------------------------------------------------------------------------

void _verifyMac(DerValue macData, Uint8List content, Uint8List senhaBmp) {
  final parts = macData.elements;
  if (parts.length < 2) return;

  final digestInfo = parts[0].elements;
  final algorithm = digestInfo[0].elements.first.oid;
  final expected = digestInfo[1].content;
  final salt = parts[1].content;
  final iterations = parts.length > 2 ? parts[2].asInt : 1;

  final hash = _hashForOid(algorithm);
  final key = pkcs12Kdf(
    hash,
    senhaBmp,
    salt,
    iterations,
    KdfPurpose.mac,
    hash.digestSize,
  );

  final computed = hmac(hash, key, content);
  if (!constantTimeEquals(expected, computed)) {
    throw PurePkcs12Exception(
      'PKCS#12 MAC mismatch: wrong password or corrupted file',
    );
  }
}

PureHash _hashForOid(String oid) {
  switch (oid) {
    case _oidSha1:
      return PureHash.sha1;
    case _oidSha256:
      return PureHash.sha256;
    default:
      throw PurePkcs12Exception('Unsupported MAC hash: $oid');
  }
}

// -----------------------------------------------------------------------------
// Decryption
// -----------------------------------------------------------------------------

Uint8List _decrypt(
  DerValue algorithm,
  Uint8List encrypted,
  _Password password,
) {
  final parts = algorithm.elements;
  final oid = parts[0].oid;

  if (oid == _oidPbes2) {
    return _decryptPbes2(parts[1], encrypted, password);
  }

  final params = parts.length > 1 ? parts[1].elements : const <DerValue>[];
  if (params.length < 2) {
    throw PurePkcs12Exception('Missing PBE parameters for $oid');
  }
  final salt = params[0].content;
  final iterations = params[1].asInt;

  Uint8List derive(int purpose, int size) => pkcs12Kdf(
        PureHash.sha1,
        password.bmp,
        salt,
        iterations,
        purpose,
        size,
      );

  switch (oid) {
    case _oidPbeSha1Rc4_128:
      return rc4(derive(KdfPurpose.key, 16), encrypted);
    case _oidPbeSha1Rc4_40:
      return rc4(derive(KdfPurpose.key, 5), encrypted);
    case _oidPbeSha1TripleDes3:
      return decryptCbc(
        TripleDesCipher(derive(KdfPurpose.key, 24)),
        derive(KdfPurpose.iv, 8),
        encrypted,
      );
    case _oidPbeSha1TripleDes2:
      return decryptCbc(
        TripleDesCipher(derive(KdfPurpose.key, 16)),
        derive(KdfPurpose.iv, 8),
        encrypted,
      );
    case _oidPbeSha1Rc2_128:
      return decryptCbc(
        Rc2Cipher(derive(KdfPurpose.key, 16), 128),
        derive(KdfPurpose.iv, 8),
        encrypted,
      );
    case _oidPbeSha1Rc2_40:
      return decryptCbc(
        Rc2Cipher(derive(KdfPurpose.key, 5), 40),
        derive(KdfPurpose.iv, 8),
        encrypted,
      );
    default:
      throw PurePkcs12Exception('Unsupported PBE algorithm: $oid');
  }
}

Uint8List _decryptPbes2(
  DerValue params,
  Uint8List encrypted,
  _Password password,
) {
  final parts = params.elements;
  if (parts.length < 2) {
    throw PurePkcs12Exception('Malformed PBES2 parameters');
  }

  final kdf = parts[0].elements;
  if (kdf[0].oid != _oidPbkdf2) {
    throw PurePkcs12Exception('Unsupported PBES2 KDF: ${kdf[0].oid}');
  }

  final kdfParams = kdf[1].elements;
  final salt = kdfParams[0].content;
  final iterations = kdfParams[1].asInt;

  int? keyLength;
  var prf = PureHash.sha1;
  for (var i = 2; i < kdfParams.length; i++) {
    final item = kdfParams[i];
    if (item.tag == 0x02) {
      keyLength = item.asInt;
    } else if (item.tag == 0x30) {
      prf = _hashForPrfOid(item.elements.first.oid);
    }
  }

  final scheme = parts[1].elements;
  final cipherOid = scheme[0].oid;
  final iv = scheme.length > 1 ? scheme[1].content : Uint8List(0);

  // PBES2 takes the password as UTF-8, not as a BMPString.
  final passwordUtf8 = Uint8List.fromList(utf8.encode(password.text));

  BlockCipher makeCipher(int size) {
    final key = pbkdf2(
      prf,
      passwordUtf8,
      salt,
      iterations,
      keyLength ?? size,
    );
    return cipherOid == _oidDesEde3Cbc
        ? TripleDesCipher(key)
        : AesCipher(key);
  }

  switch (cipherOid) {
    case _oidAes128Cbc:
      return decryptCbc(makeCipher(16), iv, encrypted);
    case _oidAes192Cbc:
      return decryptCbc(makeCipher(24), iv, encrypted);
    case _oidAes256Cbc:
      return decryptCbc(makeCipher(32), iv, encrypted);
    case _oidDesEde3Cbc:
      return decryptCbc(makeCipher(24), iv, encrypted);
    default:
      throw PurePkcs12Exception('Unsupported PBES2 cipher: $cipherOid');
  }
}

PureHash _hashForPrfOid(String oid) {
  switch (oid) {
    case _oidHmacSha1:
      return PureHash.sha1;
    case _oidHmacSha256:
      return PureHash.sha256;
    default:
      throw PurePkcs12Exception('Unsupported PBKDF2 PRF: $oid');
  }
}

String _toPem(String label, Uint8List der) {
  final b64 = base64.encode(der);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

// -----------------------------------------------------------------------------
// OIDs
// -----------------------------------------------------------------------------

const _oidData = '1.2.840.113549.1.7.1';
const _oidEncryptedData = '1.2.840.113549.1.7.6';
const _oidKeyBag = '1.2.840.113549.1.12.10.1.1';
const _oidShroudedKeyBag = '1.2.840.113549.1.12.10.1.2';
const _oidCertBag = '1.2.840.113549.1.12.10.1.3';
const _oidX509Cert = '1.2.840.113549.1.9.22.1';
const _oidLocalKeyId = '1.2.840.113549.1.9.21';
const _oidFriendlyName = '1.2.840.113549.1.9.20';

const _oidSha1 = '1.3.14.3.2.26';
const _oidSha256 = '2.16.840.1.101.3.4.2.1';
const _oidHmacSha1 = '1.2.840.113549.2.7';
const _oidHmacSha256 = '1.2.840.113549.2.9';

const _oidPbeSha1Rc4_128 = '1.2.840.113549.1.12.1.1';
const _oidPbeSha1Rc4_40 = '1.2.840.113549.1.12.1.2';
const _oidPbeSha1TripleDes3 = '1.2.840.113549.1.12.1.3';
const _oidPbeSha1TripleDes2 = '1.2.840.113549.1.12.1.4';
const _oidPbeSha1Rc2_128 = '1.2.840.113549.1.12.1.5';
const _oidPbeSha1Rc2_40 = '1.2.840.113549.1.12.1.6';

const _oidPbes2 = '1.2.840.113549.1.5.13';
const _oidPbkdf2 = '1.2.840.113549.1.5.12';
const _oidAes128Cbc = '2.16.840.1.101.3.4.1.2';
const _oidAes192Cbc = '2.16.840.1.101.3.4.1.22';
const _oidAes256Cbc = '2.16.840.1.101.3.4.1.42';
const _oidDesEde3Cbc = '1.2.840.113549.3.7';
