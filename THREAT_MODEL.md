# Modelo de ameaças

Este documento descreve os vetores de ataque considerados no design do
`dns-authority-transition`, as defesas aplicadas para cada um, e os vetores
que permanecem deliberadamente fora de escopo — com a justificativa de
custo/benefício de cada decisão.

## Ativo protegido

A integridade e a autoridade de `/etc/resolv.conf`: garantir que o arquivo
só reflete o resolvedor DNS pretendido (o da VPN quando ela está ativa, o
resolvedor local fora disso), e que nenhum outro processo — malicioso,
comprometido, ou mesmo um administrador descuidado — consegue redirecionar
silenciosamente a resolução de nomes do sistema.

## Vetores considerados e mitigados

### 1. Path injection / escrita fora de `/etc`
**Ameaça:** um bug no código, ou uma entrada inesperada, faz o processo
escrever em um caminho arbitrário do sistema.
**Mitigação:** `RESOLV_CONF` é uma constante fixa em tempo de compilação
(não vem de argumento nem de variável de ambiente), e o processo se
restringe via Landlock a só poder tocar caminhos dentro de `/etc`, com o
mínimo de permissões (`WriteFile`, `ReadFile`, `MakeReg`, `RemoveFile`)
necessário para o padrão write-then-rename.

### 2. Sobrescrita não autorizada de `resolv.conf` por outro processo
**Ameaça:** outro processo (malware, script de terceiros, erro humano)
sobrescreve o arquivo fora das janelas de transição legítimas.
**Mitigação:** o atributo `FS_IMMUTABLE_FL` (equivalente a `chattr +i`)
mantém o arquivo somente-leitura para todo o sistema, inclusive root via
shell interativo, exceto pela janela mínima em que o próprio binário está
executando uma transição.

### 3. Escrita parcial / corrompida em caso de falha (crash, queda de energia)
**Ameaça:** o processo é interrompido no meio da escrita, deixando o
arquivo em estado inconsistente ou vazio.
**Mitigação:** padrão write-then-rename — o conteúdo novo é escrito
integralmente em um arquivo temporário, sincronizado a disco (`fsync`), e
só então promovido atomicamente via `rename()`. Nunca existe um instante
em que `/etc/resolv.conf` está parcialmente escrito.

### 4. Reação a uma interface errada / interface de kill-switch
**Ameaça:** o binário reage a uma interface auxiliar da VPN (kill switch,
leak protection) em vez da interface de dados real, ou a qualquer interface
que "pareça" ser VPN.
**Mitigação:** `VPN_INTERFACE` é uma constante fixa, verificada com
comparação exata de string. Não há fallback silencioso para "qualquer
interface WireGuard" ou heurística de nome — o valor precisa ser
descoberto e confirmado manualmente pelo operador (ver README).

### 5. DNS malicioso injetado via ambiente
**Ameaça:** `IP4_NAMESERVERS` contém um valor malformado, vazio, ou um
endereço não roteável/não especificado (`0.0.0.0`), potencialmente
causando negação de serviço de DNS ou comportamento indefinido.
**Mitigação:** o valor é parseado estritamente como IPv4 e rejeitado (com
abort fail-closed, sem escrita) se for inválido ou "unspecified".

### 6. Ausência ou queda de suporte a Landlock no kernel
**Ameaça:** o binário roda em um kernel sem suporte a Landlock, ou o
sandbox não é de fato aplicado (silenciosamente ignorado).
**Mitigação:** fail-closed explícito — se `RulesetStatus::NotEnforced` for
observado após a tentativa de restrição, o processo aborta sem executar
nenhuma lógica de negócio, em vez de prosseguir sem proteção.

### 7. Substituição do binário ou do script wrapper por versão adulterada
**Ameaça:** um atacante com acesso de escrita ao filesystem (mesmo que
transitório) substitui `/usr/local/libexec/dns-authority-transition` ou o
script dispatcher por uma versão maliciosa.
**Mitigação (opcional, recomendada):** fs-verity torna os dois artefatos
permanentemente somente-leitura e verificados por hash a cada leitura,
detectando/impedindo adulteração mesmo por processos com privilégio de
root. Trade-off: atualizar exige remover e reinstalar do zero.

## Vetores deliberadamente fora de escopo

### Comprometimento do NetworkManager em si
Se o `NetworkManager-dispatcher.service` ou o próprio `NetworkManager` for
comprometido, o atacante já tem controle suficiente sobre a rede do host
para forjar qualquer evento de dispatcher, incluindo valores de
`IP4_NAMESERVERS`. Este projeto confia na integridade do NetworkManager
como pré-requisito, não como algo que reimplementa ou verifica — mitigar
isso está fora do escopo de um binário de política de DNS.

### Acesso físico / root persistente com capacidade de recompilar o kernel
Um atacante com acesso root persistente e a capacidade de recarregar
módulos de kernel, desabilitar LSMs no boot, ou reparticionar o disco pode
contornar tanto o Landlock quanto a imutabilidade do inode. Nenhuma
proteção em espaço de usuário resiste a comprometimento total do kernel;
isso é tratado como fora do modelo de ameaças (o objetivo é elevar o custo
do ataque, não torná-lo impossível contra um adversário com esse nível de
acesso).

### Ataques de rede contra o próprio protocolo DNS (spoofing, cache poisoning)
Este projeto decide *qual servidor DNS* o sistema usa; ele não valida nem
protege as respostas que esse servidor retorna. DNSSEC, DoH/DoT, e a
segurança do resolvedor local (AdGuard Home, Pi-hole, Unbound) são
responsabilidade de configuração do resolvedor escolhido, não deste
binário.

### IPv6
O binário hoje trata exclusivamente `IPv4Addr`/`IP4_NAMESERVERS`. Um
ambiente que dependa de DNS exclusivamente sobre IPv6 não está coberto —
isso é uma limitação funcional documentada, não uma falha de segurança
per se, mas vale registrar que um `resolv.conf` sem entrada IPv6 pode levar
a fallback de resolução inesperado dependendo da stack de rede do host.

### Múltiplos perfis de VPN / múltiplas interfaces simultâneas
O design atual assume uma única VPN de interesse, com nome de interface
fixo em tempo de compilação. Um cenário com múltiplas VPNs concorrentes,
prioridades entre elas, ou detecção automática de interface não é tratado
— contribuições generalizando isso são bem-vindas (ver README), mas
aumentam a superfície de decisão que precisa ser auditada com cuidado
equivalente ao já aplicado aqui.
