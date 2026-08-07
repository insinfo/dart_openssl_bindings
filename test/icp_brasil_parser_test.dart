import 'package:test/test.dart';
import 'package:openssl_bindings/openssl.dart';

void main() {
  // Real natural-person positional block: birth date 1982-01-25,
  // CPF 09498269793, zeroed NIS, zeroed ID card.
  const block = '250119820949826979300000000000000000000000000';

  group('IcpBrasilParser.extractCpfFromBlock', () {
    test('cuts the CPF at the official [8, 19) offset', () {
      expect(IcpBrasilParser.extractCpfFromBlock(block), '09498269793');
    });

    test('does not fall for the window at the start of the block', () {
      // The classic mistake: substring(0, 11) would return 25011982094.
      expect(IcpBrasilParser.extractCpfFromBlock(block), isNot('25011982094'));
    });

    test('is positional, not "the first window with valid check digits"', () {
      // Adversarial block: the birth date 19041940 followed by the first
      // three digits of the real CPF spells 19041940529, which passes the
      // check-digit maths on its own. Scanning for the first valid window
      // would return that decoy; only the official offset gets the real CPF.
      const adversarial = '190419405299822472500000000000000000000000000';

      expect(
        IcpBrasilParser.isValidCpf('19041940529'),
        isTrue,
        reason: 'the decoy has to be a genuinely valid CPF for this to bite',
      );
      expect(IcpBrasilParser.extractCpfFromBlock(adversarial), '52998224725');
    });

    test('accepts an already isolated CPF', () {
      expect(IcpBrasilParser.extractCpfFromBlock('09498269793'), '09498269793');
      expect(
        IcpBrasilParser.extractCpfFromBlock('094.982.697-93'),
        '09498269793',
      );
    });

    test('rejects a CPF with invalid check digits', () {
      expect(IcpBrasilParser.extractCpfFromBlock('09498269794'), isNull);
    });

    test('rejects a short block and a null value', () {
      expect(IcpBrasilParser.extractCpfFromBlock('2501198209'), isNull);
      expect(IcpBrasilParser.extractCpfFromBlock(null), isNull);
      expect(IcpBrasilParser.extractCpfFromBlock(''), isNull);
    });
  });

  group('IcpBrasilParser.extractCpf', () {
    test('prefers the Subject DN serialNumber', () {
      final cpf = IcpBrasilParser.extractCpf(
        subjectDn: 'CN=FULANO DE TAL:09498269793, serialNumber=09498269793, '
            'OU=Certificado PF, O=ICP-Brasil, C=BR',
        otherNameNaturalPerson: block,
      );
      expect(cpf, '09498269793');
    });

    test('falls back to the positional block when there is no serialNumber',
        () {
      expect(
        IcpBrasilParser.extractCpf(
          subjectDn: 'CN=FULANO DE TAL, O=ICP-Brasil, C=BR',
          otherNameNaturalPerson: block,
        ),
        '09498269793',
      );
    });

    test('ignores a DN serialNumber that holds a CNPJ', () {
      // On a legal-entity certificate serialNumber carries the CNPJ; the CPF
      // of the responsible still has to come from the positional block.
      expect(
        IcpBrasilParser.extractCpf(
          subjectDn: 'CN=EMPRESA LTDA, serialNumber=11222333000181, C=BR',
          otherNameResponsible: block,
        ),
        '09498269793',
      );
    });

    test('uses the responsible block on a legal-entity certificate', () {
      expect(
        IcpBrasilParser.extractCpf(
          subjectDn: 'CN=EMPRESA LTDA:12345678000195, C=BR',
          otherNameResponsible: block,
        ),
        '09498269793',
      );
    });

    test('returns null when there is nothing usable', () {
      expect(
        IcpBrasilParser.extractCpf(subjectDn: 'CN=SEM IDENTIFICADOR'),
        isNull,
      );
      expect(IcpBrasilParser.extractCpf(), isNull);
    });
  });

  group('IcpBrasilParser.extractCnpj', () {
    test('reads from the otherName', () {
      expect(
        IcpBrasilParser.extractCnpj(otherNameCnpj: '11222333000181'),
        '11222333000181',
      );
    });

    test('reads from the DN serialNumber', () {
      expect(
        IcpBrasilParser.extractCnpj(
          subjectDn: 'CN=EMPRESA LTDA, serialNumber=11222333000181, C=BR',
        ),
        '11222333000181',
      );
    });

    test('rejects a CNPJ with bad check digits and repeated digits', () {
      expect(
        IcpBrasilParser.extractCnpj(otherNameCnpj: '11222333000182'),
        isNull,
      );
      expect(
        IcpBrasilParser.extractCnpj(otherNameCnpj: '11111111111111'),
        isNull,
      );
    });
  });

  group('Other fields of the positional block', () {
    // Birth date 1975-03-12, CPF 52998224725, NIS 12345678901,
    // ID card 000000012345678.
    const full = '120319755299822472512345678901000000012345678';

    test('reads DDMMYYYY from the start of the block', () {
      expect(
        IcpBrasilParser.extractBirthDate(block),
        DateTime.utc(1982, 1, 25),
      );
      expect(
        IcpBrasilParser.extractBirthDate(full),
        DateTime.utc(1975, 3, 12),
      );
    });

    test('rejects an impossible date', () {
      expect(
        IcpBrasilParser.extractBirthDate(
          '310219820949826979300000000000000000000000000',
        ),
        isNull,
      );
    });

    test('reads NIS and ID card', () {
      expect(IcpBrasilParser.extractNis(full), '12345678901');
      expect(IcpBrasilParser.extractIdCard(full), '12345678');
    });

    test('zeroed fields read as absent, not as a string of zeroes', () {
      expect(IcpBrasilParser.extractNis(block), isNull);
      expect(IcpBrasilParser.extractIdCard(block), isNull);
    });
  });

  group('Masking for logs', () {
    test('CPF keeps only the middle digits', () {
      expect(IcpBrasilParser.maskCpf('09498269793'), '***.982.697-**');
      expect(IcpBrasilParser.maskCpf('094.982.697-93'), '***.982.697-**');
    });

    test('CNPJ keeps only the middle digits', () {
      expect(IcpBrasilParser.maskCnpj('11222333000181'), '**.222.333/0001-**');
    });

    test('a malformed value never leaks in full', () {
      expect(IcpBrasilParser.maskCpf('1234'), '');
      expect(IcpBrasilParser.maskCpf(null), '');
      expect(IcpBrasilParser.maskCnpj('11222333'), '');
    });
  });

  group('Validators', () {
    test('CPF', () {
      expect(IcpBrasilParser.isValidCpf('09498269793'), isTrue);
      expect(IcpBrasilParser.isValidCpf('00000000000'), isFalse);
      expect(IcpBrasilParser.isValidCpf('123'), isFalse);
    });

    test('CNPJ', () {
      expect(IcpBrasilParser.isValidCnpj('11222333000181'), isTrue);
      expect(IcpBrasilParser.isValidCnpj('11222333000180'), isFalse);
    });
  });

  group('Certificate integration', () {
    late OpenSSL openSsl;

    setUp(() => openSsl = OpenSSL());

    X509Certificate certificateWith(List<X509OtherName> otherNames,
        {String commonName = 'FULANO DE TAL'}) {
      final key = openSsl.generateRsa(2048);
      return (X509CertificateBuilder(openSsl)
            ..setSubject(commonName: commonName)
            ..setIssuerAsSubject()
            ..setPublicKey(key)
            ..setValidity(notAfterOffset: 3600)
            ..addSubjectAltNameOtherNames(otherNames))
          .sign(key);
    }

    test('returns the normalized CPF, the raw block and the birth date', () {
      final cert = certificateWith(
        [X509OtherName(IcpBrasilParser.oidNaturalPerson, block)],
        commonName: 'FULANO DE TAL:09498269793',
      );

      final info = cert.icpBrasilInfo;
      expect(info.cpf, '09498269793');
      expect(info.cpfOtherNameRaw, block);
      expect(info.birthDate, DateTime.utc(1982, 1, 25));
      expect(info.isLegalEntity, isFalse);
      // toString is log-safe: the parsed CPF never appears in it.
      expect(info.toString(), contains('cpf: ***'));
    });

    test('a legal-entity certificate exposes CNPJ, company and responsible',
        () {
      final cert = certificateWith(
        [
          X509OtherName(IcpBrasilParser.oidCnpj, '11222333000181'),
          X509OtherName(IcpBrasilParser.oidLegalEntityResponsible, block),
          X509OtherName(
            IcpBrasilParser.oidLegalEntityResponsibleName,
            'FULANO DE TAL',
          ),
          X509OtherName(IcpBrasilParser.oidCompanyName, 'EMPRESA LTDA'),
        ],
        commonName: 'EMPRESA LTDA:11222333000181',
      );

      final info = cert.icpBrasilInfo;
      expect(info.cnpj, '11222333000181');
      expect(info.isLegalEntity, isTrue);
      expect(info.companyName, 'EMPRESA LTDA');
      expect(info.responsibleName, 'FULANO DE TAL');
      // The responsible's CPF comes from their own positional block.
      expect(info.cpf, '09498269793');
    });

    test('OID 2.16.76.1.3.6 is read as the CEI, not as a birth date', () {
      // Up to 0.6.0 this OID fed the birth date, while DOC-ICP-04 defines it
      // as the INSS registration.
      final cert = certificateWith(
        [X509OtherName(IcpBrasilParser.oidNaturalPersonCei, '123456789012')],
      );

      final info = cert.icpBrasilInfo;
      expect(info.cei, '123456789012');
      expect(info.birthDate, isNull);
    });
  });
}
