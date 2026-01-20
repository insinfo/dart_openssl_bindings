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
- `CryptoMixin`: Geração e carregamento de chaves.
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

### Fase 3: PKI (X509) (Concluído)
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

