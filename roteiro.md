# Roteiro de Implementação: Bindings OpenSSL Orientado a Objetos (SOLID)

Este roteiro detalha a arquitetura refatorada para transformar os bindings FFI em uma API orientada a objetos, modular e testável, utilizando Mixins (Partial Classes) e Injeção de Dependência.

regra geral: sempre editar o arquivo C:\MyDartProjects\openssl_bindings\ffigen.yaml colocar as funções necessarias
e gerar o binding com dart run ffigen --config ffigen.yaml

## 1. Arquitetura e Estrutura

A arquitetura abandona o padrão Singleton estático em favor de um Contexto (`OpenSSL`) instanciável. Isso permite:
- **Testabilidade**: Facilita mocking e injeção de dependência.
- **Flexibilidade**: Permite carregar DLLs de caminhos arbitrários passados no construtor.
- **Isolamento**: Objetos criados por uma instância `OpenSSL` usam os bindings daquela instância específica.

### Estrutura de Diretórios
```
lib/
  openssl_bindings.dart        # Export principal
  src/
    api/
      openssl.dart             # Classe Principal (Contexto + Mixins)
      openssl_context.dart     # Interface do Contexto (Contrato)
      mixins/
        bio_mixin.dart         # Funcionalidades de IO (BIO operations)
        crypto_mixin.dart      # Funcionalidades de Criptografia (Keys, Keygen)
        asn1_mixin.dart        # Funcionalidades ASN.1 (DER encode/decode via OpenSSL)
        signature_mixin.dart   # (Planejado) Assinatura e Verificação
        x509_mixin.dart        # (Planejado) Funcionalidades de Certificados
    
    crypto/
      evp_pkey.dart            # Wrapper de Objeto (Recebe OpenSSL context no construtor)
      
    infra/
      openssl_lib.dart         # Loader de baixo nível (interno)
      ssl_object.dart          # Base para wrappers com NativeFinalizer
      ssl_exception.dart       # Tratamento de erros
```

## 2. Componentes Principais

### 2.1. Classe `OpenSSL` (Fachada e Contexto)
A classe `OpenSSL` atua como a entrada principal da library.
- **High Cohesion**: Agrega funcionalidades específicas via Mixins (`with BioMixin, CryptoMixin`).
- **Dependency Injection**: Passa a si mesma (`this`) para os objetos que cria (ex: `EvpPkey`), permitindo que esses objetos acessem os bindings corretos para operações como `saveToPem` ou `free`.

### 2.2. Wrappers Inteligentes (`SslObject`)
Objetos como `EvpPkey` ou `X509Certificate` deixam de ser coleções de métodos estáticos.
- **Estado Imutável**: O ponteiro nativo e o contexto são finais.
- **NativeFinalizer**: O hook de limpeza é configurado usando o endereço da função `free` obtido do contexto específico.

### 2.3. Mixins (Segregação de Interface)
Para evitar uma "God Class", as funcionalidades são separadas:
- `BioMixin`: Manipulação de memória e buffers OpenSSL.
- `CryptoMixin`: Geração e carregamento de chaves (RSA, EC), com suporte a chaves criptografadas (senha).
- `X509Mixin`: Parsing e manipulação de certificados (Obter Subject, Issuer, Serial, Datas).
- `CmsMixin`: Operações CMS/PKCS#7, incluindo assinatura de hash pré-calculado (Digest Signing) e validação de cadeia.

## 3. Estado da Implementação

### 3.1. Funcionalidades Faltantes (Prioridade Alta)
*Todas as funcionalidades de alta prioridade foram implementadas e validadas.*

1.  **Encrypted Private Keys**: Implementado em `CryptoMixin.loadPrivateKeyPem`.
2.  **X509 Details**: Implementado em `X509Certificate` getters.
3.  **CMS Digest Signing**: Implementado `signDetachedDigest` no `CmsMixin`.
4.  **Trust Store Validation**: Implementado `X509Store` e integrado em `verifyCmsDetached`.

## 4. Testes e Validação
- Criado `test/validation_test.dart` cobrindo os 4 cenários principais.

---

## 5. Histórico da Implementação

### Fase 1: Infraestrutura (Concluído)
- [x] Loader Dinâmico (`openssl_lib.dart`).
- [x] Classe Base `SslObject` com `NativeFinalizer`.
- [x] Tratamento de Erros (`SslException`).
- [x] Arquitetura de Mixins (`OpenSslContext`, `OpenSSL`).
- [x] Mixin de IO (`BioMixin`) com testes.

### Fase 2: Criptografia Core (Concluído)
- [x] Wrapper `EvpPkey` refatorado para OO.
- [x] Geração de Chaves RSA (via `CryptoMixin`).
- [x] Exportação/Importação PEM (Privada/Pública).
- [x] **Carregamento de Chaves Criptogradas (Senha)**.
- [x] **Mixin de Assinatura (`SignatureMixin`)**.
    - Assinar dados (SHA256).
    - Verificar assinaturas.

### Fase 3: ASN.1 (Concluído)
- [x] **Mixin ASN.1 (`Asn1Mixin`)**.
  - Encode DER (X509, X509_NAME, ASN1_INTEGER).
  - Decode DER (X509 via d2i).
  - Helpers para issuer/serial em DER.

### Fase 4: PKI (X509) (Concluído)
- [x] Implementar `X509Mixin`.
- [x] Wrapper `X509Certificate`.
    - [x] Getters: `subject`, `issuer`, `serialNumber`, `notBefore`, `notAfter`.
- [x] Wrapper `X509Name` (Subject/Issuer).
- [x] Builder de Certificados (`X509CertificateBuilder`).
    - [x] Self-Signed.
    - [x] Definição de Subject/Issuer.
    - [x] Assinatura.
- [x] **Trust Store (`X509Store`)**.

### Fase 5: CMS (PKCS#7) (Concluído)
- [x] Implementar `CmsMixin`.
- [x] **Digest Signing**: `signDetachedDigest` (Assinatura de Hash pré-calculado).
- [x] Validação (`verifyCmsDetached`) com suporte a `X509Store`.

## 6. Próximos Passos (Possíveis Expansões)
1. **CSR (Certificate Signing Request)**: Permitir gerar `.csr` para enviar a uma CA real.
2. **Escrita de Chaves Criptografadas**: Implementar `savePrivateKeyPem({String? password})`.
3. **Validação de Cadeia Completa**: Expor detalhes da validação (erros específicos baseados na flag de verify).

## 6. Próximos Passos (Expansão General Purpose - Substituir PointyCastle)

Para tornar a library uma solução completa de criptografia, as seguintes funcionalidades serão implementadas:

### 6.1. Criptografia Simétrica (AES)
- [x] **AES-GCM**: Implementado e Testado (ver `test/cipher_test.dart` e `CipherMixin`).
- **AES-CBC (Cipher Block Chaining)**: Suporte legado (com PKCS#7 padding).

### 6.2. Derivação de Chaves (KDF)
- [x] **PBKDF2**: Gerar chaves seguras a partir de chaves/senhas (`CryptoMixin.pbkdf2`).

### 6.3. Hashing e MAC
- [x] **Hashing Genérico**: `CryptoMixin.digest` (SHA-256, etc).
- [x] **HMAC**: `CryptoMixin.hmac` (Autenticação de mensagens).

### 6.4. Criptografia Assimétrica Moderna (ECC)
- [x] **Chaves EC**: `CryptoMixin.generateEc` (Lookup dinâmico de funções de KDF/Keygen para OpenSSL 3).
- **ECDH**: Troca de chaves Diffie-Hellman.

## 7. Histórico da Implementação
- implementar funcionalidades para converção de formatos de certificados como .crt, .der, .pem .p7b PEM, DER, CRT e CER, pfx PKCS12: Codificações e conversões X.509  Os formatos .pem, .crt, .der e .p7b são extensões comuns para arquivos de certificados digitais SSL/TLS .pem (Privacy-Enhanced Mail): Formato ASCII Base64 mais popular, frequentemente usado no Apache/Linux. Contém cabeçalhos -----BEGIN CERTIFICATE-----.
.crt (Certificate): Similar ao PEM, usado comumente para certificados únicos. Pode conter dados PEM ou DER.
.der (Distinguished Encoding Rules): Formato binário do certificado. Não é legível em editores de texto e é comum em plataformas Java.
.p7b (PKCS#7): Arquivo ASCII Base64, usado principalmente no Windows/Java para armazenar apenas certificados (pública + intermediários), sem a chave privada. 
Esses formatos podem ser convertidos entre si usando ferramentas como o OpenSSL. 
 - [x] implementar conversão PEM/DER/CRT/CER e auto-detecção de bytes (X509)
 - [x] implementar funcionalidades para extrair certificados de .p7b (PKCS#7/CMS)
 - [x] implementar funcionalidades para ler/gravar PKCS#12/PFX
 - [x] implementar funcionalidades para extrair informações de certificados ICP-BRASIL como nome, CPF, data de nascimento, politicas etc

- [x] Expor extraCertsDer e hashAlgorithm diretamente em CmsMixin.signDetachedDigest (hoje isso só está em CmsPkcs7Signer, então o mixin não deixa incluir cadeia). Veja cms_mixin.dart e cms_pkcs7_signer.dart.
- [x] Builder de extensões X.509 (SAN otherName, CRL/OCSP URLs, policies) para substituir o fluxo que hoje usa dart_pdf/basic_utils para emissão de certificados. Veja x509_builder.dart.
- [x] Helpers utilitários para “cadeia PEM → lista de X509Certificate/DER” ( facilita substituir basic_utils).


Possíveis lacunas de API para o seu cenário:

Extensões KeyUsage e ExtendedKeyUsage no builder de certificado não aparecem em x509_builder.dart. Isso é usado no seu código para CA/usuario, então vale implementar.
CmsMixin.signDetached não expõe extraCertsDer/hashAlgorithm; você pode usar direto cms_pkcs7_signer.dart ou adicionar overload no mixin.
Testes que eu adicionaria para ficar mais próximo do seu uso real:

signDetachedDigest + verifyCmsDetached (incluindo cadeia) em cms_test.dart
Falhas de validação com verifyCmsDetachedWithResult em cms_test.dart
X.509 com SAN otherName + policies + (depois) KeyUsage/ExtendedKeyUsage em x509_certificate_builder_test.dart
PKCS#12 com senha inválida em pkcs_test.dart
Se quiser, implemento essas APIs e testes aqui.