# Roteiro de Implementação: Bindings OpenSSL Orientado a Objetos (SOLID)

Este roteiro detalha a arquitetura refatorada para transformar os bindings FFI em uma API orientada a objetos, modular e testável, utilizando Mixins (Partial Classes) e Injeção de Dependência.

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

## 3. Próximos Passos (Implementação)

### 3.1. Funcionalidades Faltantes (Prioridade Alta)
1.  **Encrypted Private Keys**: Atualizar `CryptoMixin.loadPrivateKeyPem` para aceitar `password`.
    - Usar 4º argumento de `PEM_read_bio_PrivateKey` como string de senha.
2.  **X509 Details**: Implementar getters na classe `X509Certificate`.
    - `subject` / `issuer`: Usar `X509_get_{subject,issuer}_name` e `X509_NAME_oneline`.
    - `serialNumber`: Usar `X509_get_serialNumber` e conversão BIGNUM.
    - `validity`: Usar `X509_getm_notBefore` / `X509_getm_notAfter`.
3.  **CMS Digest Signing**: Implementar `signDetachedDigest` no `CmsMixin`.
    - Permitir assinar um hash SHA-256 já calculado (necessário para PDFs grandes/PAdES).
4.  **Trust Store Validation**: Melhorar `verifyCmsDetached` para aceitar lista de raízes.
    - Criar abstração `OpenSqlX509Store`.

## 4. Testes e Validação
- Criar testes unitários para cada nova funcionalidade implementada.
- Validar interoperabilidade com arquivos reais (Certificado do Gov.br, etc).
- `CryptoMixin`: Geração e carregamento de chaves.
- `Asn1Mixin`: Encode/decode DER via APIs ASN.1 do OpenSSL.
- `X509Mixin`: Operações de certificados.

---

## 3. Estado da Implementação

### Fase 1: Infraestrutura (Concluído)
- [x] Loader Dinâmico (`openssl_lib.dart`).
- [x] Classe Base `SslObject` com `NativeFinalizer`.
- [x] Tratamento de Erros (`SslException`).
- [x] Arquitetura de Mixins (`OpenSslContext`, `OpenSSL`).
- [x] Mixin de IO (`BioMixin`) com testes.

### Fase 2: Criptografia Core (Em Progresso)
- [x] Wrapper `EvpPkey` refatorado para OO.
- [x] Geração de Chaves RSA (via `CryptoMixin`).
- [x] Exportação/Importação PEM (Privada/Pública).
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
- [x] Wrapper `X509Name` (Subject/Issuer).
- [x] Builder de Certificados (`X509CertificateBuilder`).
    - [x] Self-Signed.
    - [x] Definição de Subject/Issuer.
    - [x] Assinatura.

## 4. Próximos Passos (Possíveis Expansões)
1. **CSR (Certificate Signing Request)**: Permitir gerar `.csr` para enviar a uma CA real.
2. **Assinatura de CA**: Permitir que uma chave CA assine um CSR ou um certificado de outra entidade.
3. **Validação**: Verificar chain de certificados (Root -> Intermediate -> Leaf).


Com base na análise do seu código atual e do estado atual da biblioteca openssl_bindings, identifiquei as seguintes lacunas (APIs faltantes) que precisam ser implementadas para que você possa substituir pdfbox_dart, asn1lib e pointycastle:

1. Assinatura de Hash Pré-calculado (Para PAdES/PDF)
O seu PdfAssinaturaInternaService calcula o hash do byte range do PDF (_computeByteRangeDigest) e pede para assinar esse digest.

O que falta: A openssl_bindings atualmente suporta signDetached (que recebe o conteúdo completo e faz o hash internamente). Faltam métodos para assinar um hash já calculado (Digest Signing).
Necessário implementar: Uma função que monte a estrutura CMS/PKCS#7 manualmente (usando CMS_sign com flag CMS_PARTIAL ou CMS_add1_signer) e insira o atributo autenticado messageDigest com o hash que você calculou no Dart.
2. Leitura de Chaves Privadas Criptografadas
Seu código atual usa pointycastle e PBKDF2 para decifrar chaves PEM manualmente (_decryptPrivateKeyPem).

O que falta: Suporte a senha no método CryptoMixin.loadPrivateKeyPem.
Necessário implementar: Atualizar o wrapper para aceitar um argumento password e passá-lo para a função nativa PEM_read_bio_PrivateKey (que já existe nos bindings, mas está sendo chamada com nullptr para a senha).
3. Inspeção de Detalhes do Certificado X.509
Seus controllers (GovBrAssinaturaController, ValidacaoAssinaturaController) extraem campos como Subject, Issuer, Serial Number, Common Name e datas de validade para exibir na tela e validar.

O que falta: A classe X509Certificate atualmente só tem o método toPem().
Necessário implementar: Getters na classe X509Certificate que chamem as funções nativas:
subject (via X509_get_subject_name)
issuer (via X509_get_issuer_name)
serialNumber (via X509_get_serialNumber)
notBefore / notAfter (via X509_get0_notBefore / X509_get0_notAfter)
4. Validação de Cadeia com TrustStore Dinâmico
Seu serviço de validação (AssinaturaValidacaoService) carrega listas de PEMs confiáveis (Gov.br, ICP-Brasil) dinamicamente.

O que falta: O método verifyCmsDetached atual aceita apenas um único certificado confiável (trustedCertDer).
Necessário implementar: Uma abstração de X509Store onde você possa adicionar múltiplos certificados (AC Raiz e Intermediárias) e passar essa store para a função de verificação.
Resumo do Plano de Ação
Para abandonar as outras libs, precisamos evoluir a openssl_bindings com:

Wrapper de X509: Adicionar getters de texto (Subject, Issuer, Serial).
Wrapper de Crypto: Suportar senha em loadPrivateKeyPem.
Wrapper de CMS: Criar signDetachedDigest(digestBytes, ...)
Store de Certificados: Permitir validação contra múltiplas raízes.
Gostaria de começar implementando a leitura de detalhes do certificado (X509) ou prefere focar na assinatura do hash (CMS) primeiro?