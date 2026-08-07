# CLAUDE.md

Instruções para agentes de IA trabalhando neste repositório.

## Commits e Pull Requests

**NUNCA adicione linhas de atribuição/assinatura de IA ao final de mensagens de commit, descrições de PR, issues ou comentários.**

Isso inclui, mas não se limita a:

- `Co-Authored-By: Claude <noreply@anthropic.com>` (ou qualquer variante `Co-Authored-By` de IA)
- `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- `Generated with ...`, `Created by ...`, `Assisted by ...`
- Emojis de robô, badges ou links promocionais de ferramentas de IA

As mensagens de commit devem conter apenas a descrição da mudança, no formato
[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
`docs:`, `ci:`, `refactor:`, `test:`, `chore:`), e nada mais.

Exemplo correto:

```
feat: add OCSP/CRL client APIs and cache TTL fix
```

Exemplo incorreto:

```
feat: add OCSP/CRL client APIs and cache TTL fix

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

O único autor registrado deve ser o autor configurado no git local.

## Idioma

**A API pública e os comentários do código são em inglês.** Nomes de classes,
métodos, parâmetros, variáveis, mensagens de exceção, dartdoc e descrições de
teste — tudo em inglês, como no restante do pacote e como espera quem consome
pelo pub.dev.

Português fica restrito a este arquivo e à conversa com o time; não entra em
`lib/`, `test/` nem no `CHANGELOG.md`.

## Bindings FFI

**NUNCA escreva bindings FFI à mão.** Todo símbolo novo do OpenSSL deve ser
adicionado ao [ffigen.yaml](ffigen.yaml) e os bindings regerados:

```sh
dart run ffigen --config ffigen.yaml
```

Regras:

- `lib/src/generated/ffi.dart` é **gerado** — não edite manualmente; qualquer
  edição à mão é perdida na próxima geração.
- Precisa de uma função nova? Acrescente o nome em `functions.include`. Se o
  símbolo estiver num header ainda não listado, acrescente o header em
  `headers.entry-points` também.
- Macros/constantes vão em `macros.include`.
- Não crie arquivos de binding paralelos (`DynamicLibrary.lookup` solto,
  `ffigen_*.yaml` extras) para contornar a geração — usar um único
  `ffigen.yaml` e um único `ffi.dart`.
- Pré-requisitos locais da geração: LLVM em `C:/LLVM` e headers do OpenSSL em
  `C:/Program Files/OpenSSL-Win64/include` (caminhos configurados no
  `ffigen.yaml`).
- Confira o diff depois de gerar: ele deve conter apenas os símbolos novos.
