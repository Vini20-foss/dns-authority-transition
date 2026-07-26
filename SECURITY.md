# Security Policy

## Escopo

Este projeto manipula `/etc/resolv.conf` como root e aplica sandboxing via
Landlock. Vulnerabilidades relevantes incluem, mas não se limitam a:

- Escrita fora de `/etc` (bypass de sandbox Landlock)
- Bypass da imutabilidade dinâmica do inode
- Escrita parcial/corrompida de `resolv.conf` (falha do padrão write-then-rename)
- Aceitação de valores de DNS inválidos ou maliciosos vindos do ambiente
- Qualquer caminho que permita escrita sem que `apply_landlock_sandbox()`
  tenha sido aplicado com sucesso

Veja [`THREAT_MODEL.md`](THREAT_MODEL.md) para o modelo de ameaças completo,
incluindo vetores deliberadamente fora de escopo.

## Versões suportadas

| Versão | Suportada |
| ------ | --------- |
| 0.1.x  | :white_check_mark: |

Projeto em estágio de protótipo (ver README, seção "Status do projeto").
Não há garantia de compatibilidade entre versões `0.x` até a primeira
release estável.

## Reportando uma vulnerabilidade

Abra uma [issue](https://github.com/Vini20-foss/dns-authority-transition/issues)
descrevendo o vetor encontrado. Para vulnerabilidades que exponham risco
imediato (ex: bypass do sandbox permitindo escrita fora de `/etc`), marque
a issue como sensível ou entre em contato diretamente com o mantenedor
antes de detalhar publicamente os passos de exploração.
