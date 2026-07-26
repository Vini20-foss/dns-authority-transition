# Modelo de ameaça

Este documento descreve os vetores de ataque considerados no desenho deste
projeto, o que cada camada mitiga, e os vetores que permanecem
deliberadamente em aberto — com a justificativa de custo/benefício de cada
decisão.

## Premissas

- O binário roda como root, disparado pelo dispatcher do NetworkManager
  (que já roda como root).
- O objetivo é impedir que um bug neste código, ou um processo malicioso
  não relacionado à VPN, altere `/etc/resolv.conf` fora dos momentos
  controlados de transição.
- Não assumimos que o usuário já está comprometido por um atacante com
  persistência de root — esse cenário está fora do escopo (ver seção
  "Vetores fora de escopo" abaixo).

## Camadas de defesa e o que cada uma mitiga

| Camada | Mitiga |
|---|---|
| Landlock | O binário, mesmo comprometido por um bug próprio, não consegue escrever fora de `/etc` |
| Fail-closed | Qualquer falha de validação aborta sem escrever, preservando o estado anterior |
| Write-then-rename | Elimina qualquer janela de arquivo parcialmente escrito |
| Imutabilidade dinâmica (chattr via ioctl) | Nenhum outro processo, nem root via shell direto, escreve em `resolv.conf` fora da janela de transição |
| fs-verity (opcional) | Impede substituição do binário ou do wrapper por uma versão adulterada |

## Vetores considerados e mitigados

1. **Substituição do binário por um processo malicioso já com root** —
   mitigado por fs-verity, se habilitado. Sem fs-verity, este é o vetor
   mais direto e o principal motivo de recomendarmos habilitá-lo.
2. **Substituição do script wrapper** — mesmo tratamento que o item acima.
   O wrapper é texto plano e, sem fs-verity, é o elo mais fácil de atacar
   (editar 2 linhas de bash é mais simples que recompilar/substituir um
   binário ELF).
3. **Escrita direta em `resolv.conf` por qualquer processo fora do binário**
   — mitigado pela imutabilidade dinâmica. Validado empiricamente: mesmo
   `sudo bash -c 'echo ... > /etc/resolv.conf'` falha com "Operation not
   permitted" enquanto o arquivo está no estado de repouso imutável.
4. **Execução do binário sem privilégio suficiente** — falha
   deterministicamente (permissão negada ao tentar escrever), sem deixar
   estado inconsistente.
5. **Kernel sem suporte a Landlock** — o binário recusa-se a rodar, em vez
   de prosseguir sem a sandbox.

## Vetores residuais, deliberadamente não mitigados

Estes vetores foram avaliados e a decisão foi não investir mitigação
adicional, pela razão descrita em cada um.

1. **Race condition na janela de mutabilidade.** Existe uma janela de
   poucos milissegundos, durante a execução do binário, em que o arquivo
   está gravável. Um processo que monitorasse `resolv.conf` via `inotify`
   em tempo real poderia, em teoria, tentar escrever nesse intervalo.
   *Por que não mitigamos*: exploração exigiria já ter root e estar
   ativamente monitorando o sistema; o ganho para o atacante (alterar
   temporariamente um DNS) é desproporcional ao esforço, frente a outras
   ações que esse nível de acesso já permitiria.

2. **Validação apenas sintática do valor de `IP4_NAMESERVERS`.** O binário
   valida que o valor é um IPv4 bem formado e rejeita `0.0.0.0`, mas não
   verifica se o IP pertence a um range conhecido do provedor de VPN.
   *Por que não mitigamos*: exploração exigiria injetar uma variável de
   ambiente forjada especificamente no processo `nm-dispatcher` antes dele
   invocar o wrapper — o que, com fs-verity ativo no wrapper, já exigiria
   comprometer o próprio NetworkManager, um alvo com superfície muito maior
   e mais valiosa que este binário.

## Vetores fora de escopo

Um atacante que já tenha conseguido execução de código persistente como
root no sistema (por qualquer via não relacionada a este projeto) tem à
disposição objetivos muito mais valiosos do que adulterar temporariamente
a resolução de DNS: leitura de qualquer arquivo, exfiltração de dados,
instalação de outros implantes. Este projeto não pretende ser uma defesa
contra um sistema já comprometido em nível de root — pretende ser uma
camada de robustez contra bugs próprios e processos não privilegiados ou
semi-privilegiados que tentem interferir na configuração de DNS.
