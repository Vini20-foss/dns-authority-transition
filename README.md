# dns-authority-transition

Transição automática e segura da autoridade DNS do sistema ao conectar/desconectar
uma VPN gerenciada via NetworkManager em Linux.

## O problema que isso resolve

Se você roda um resolvedor DNS local (AdGuard Home, Pi-hole, Unbound, etc.) e
também usa uma VPN, provavelmente já bateu numa destas situações:

- Configurar a VPN para usar seu resolvedor local funciona, mas quebra
  qualquer recurso da VPN que dependa do DNS dela própria (ex: geo-roteamento
  de servidores, bypass de bloqueio geográfico).
- Deixar a VPN usar o DNS dela funciona para esses recursos, mas você perde
  o filtro de anúncios/rastreadores do seu resolvedor local enquanto a VPN
  está ativa.
- Trocar manualmente entre as duas opções toda vez que conecta/desconecta
  é tedioso e você esquece de fazer isso na maioria das vezes.

Este projeto automatiza a troca: quando sua VPN conecta, o sistema passa a
usar o DNS dela; quando desconecta, volta automaticamente para o seu
resolvedor local — sem intervenção manual, com múltiplas camadas de proteção
contra escrita não autorizada em `/etc/resolv.conf`.

## Como funciona

Um binário Rust, chamado por um script mínimo registrado como dispatcher do
NetworkManager, reage a cada evento de conexão/desconexão de rede. Quando
detecta que a interface da sua VPN subiu, lê o DNS que o próprio
NetworkManager já expõe no ambiente do dispatcher (`IP4_NAMESERVERS`) e
escreve isso em `/etc/resolv.conf`. Quando a interface desce, reverte para
o IP do seu resolvedor local.

## Modelo de segurança

Este não é um script simples de troca de arquivo. Ele foi desenhado com
múltiplas camadas independentes de defesa em profundidade:

1. **Landlock (LSM)** — o binário se autorrestringe, via kernel, a só poder
   escrever dentro de `/etc`. Mesmo rodando como root, um bug no código não
   consegue tocar em nenhum outro caminho do sistema de arquivos.
2. **Fail-closed em toda etapa** — qualquer falha (permissão negada, kernel
   sem suporte a Landlock, variável de ambiente ausente ou inválida) aborta
   a execução sem escrever nada. O estado anterior do `resolv.conf`
   permanece válido.
3. **Escrita atômica (write-then-rename)** — nunca existe um instante em
   que o arquivo está parcialmente escrito.
4. **Imutabilidade dinâmica do inode** — `/etc/resolv.conf` permanece com o
   atributo `FS_IMMUTABLE_FL` (o mesmo que `chattr +i`) o tempo todo, exceto
   pela janela mínima em que o próprio binário está escrevendo uma
   transição. Isso significa que **nenhum outro processo do sistema**,
   nem mesmo root via shell interativo, consegue sobrescrever o arquivo
   fora dessas janelas controladas.
5. **fs-verity nos artefatos** — recomendado (veja abaixo) para impedir que
   o próprio binário ou o script wrapper sejam substituídos por uma versão
   adulterada, mesmo por um processo com privilégio de root.

Veja [`THREAT_MODEL.md`](THREAT_MODEL.md) para uma descrição completa dos
vetores de ataque considerados e dos que permanecem deliberadamente em
aberto (com a justificativa de custo/benefício de cada decisão).

## Status do projeto

**Protótipo funcional, testado em um único ambiente.** Este código foi
desenvolvido e validado pelo autor em um ambiente específico: Arch Linux
(derivado), kernel com suporte a Landlock ABI v5, filesystem Btrfs, um
cliente de VPN comercial gerenciado via NetworkManager, e um resolvedor DNS
local rodando em container.

Ele **não é plug-and-play** para qualquer combinação de VPN/sistema. As
constantes `VPN_INTERFACE` e `FALLBACK_DNS` em `src/main.rs` são específicas
do seu ambiente e precisam ser descobertas e ajustadas manualmente — veja a
seção abaixo.

Contribuições generalizando o mecanismo (configuração externa, detecção
automática de interface, suporte a múltiplos perfis de VPN) são bem-vindas
via issues e pull requests.

## Pré-requisitos

- Linux com NetworkManager gerenciando sua conexão de VPN
- Kernel com suporte a Landlock (5.13+; verifique com
  `cat /sys/kernel/security/lsm | grep landlock`)
- Rust/Cargo instalado
- Um resolvedor DNS local já configurado e funcional (este projeto não
  instala nem configura um para você)
- Opcional, mas recomendado: `fsverity-utils`, e um filesystem com suporte a
  fs-verity (ext4, f2fs ou btrfs 5.15+)

## Descobrindo os valores para sua VPN

Antes de compilar, você precisa descobrir dois valores específicos do seu
ambiente: o nome real da interface de rede que sua VPN cria, e confirmar que
o NetworkManager expõe o DNS dela via `IP4_NAMESERVERS` no ambiente do
dispatcher.

1. Crie um script de debug temporário, **somente leitura**, para observar o
   que o NetworkManager realmente expõe:

   ```bash
   sudo tee /etc/NetworkManager/dispatcher.d/99-debug-vpn.sh > /dev/null << 'SCRIPT'
   #!/bin/bash
   {
     echo "=== $(date) ==="
     echo "INTERFACE: $1"
     echo "ACTION: $2"
     env | grep -E '^(DHCP4|CONNECTION|DEVICE|IP4|VPN)_'
     echo "==="
   } >> /tmp/nm-dispatcher-debug.log
   SCRIPT
   sudo chmod 750 /etc/NetworkManager/dispatcher.d/99-debug-vpn.sh
   sudo systemctl restart NetworkManager-dispatcher.service
   ```

2. Desconecte e reconecte sua VPN pela interface normal (GUI ou CLI).

3. Leia o log:

   ```bash
   grep -E "INTERFACE:|ACTION:|IP4_NAMESERVERS|CONNECTION_ID" /tmp/nm-dispatcher-debug.log
   ```

4. Procure a entrada com `ACTION: up` para a interface da sua VPN (não as
   interfaces auxiliares de kill switch, se sua VPN criar alguma — elas
   geralmente têm nomes como `*ksintrf*` ou `*leakintrf*` e não são a
   interface de dados real). Anote:
   - O valor de `INTERFACE:` → isso vai em `VPN_INTERFACE`
   - O valor de `IP4_NAMESERVERS=` nessa mesma entrada, só para confirmar
     que existe e é um IP válido (o valor em si você não precisa hardcodar
     em lugar nenhum — o binário lê isso dinamicamente a cada execução)

5. **Remova o script de debug** depois de capturar os dados:

   ```bash
   sudo rm /etc/NetworkManager/dispatcher.d/99-debug-vpn.sh
   sudo rm /tmp/nm-dispatcher-debug.log
   sudo systemctl restart NetworkManager-dispatcher.service
   ```

Se sua VPN **não** expuser `IP4_NAMESERVERS` no ambiente do dispatcher
(algumas VPNs baseadas em `wg-quick` com hooks próprios, em vez de
integração nativa com NetworkManager, podem não fazer isso), este mecanismo
não se aplica diretamente ao seu caso sem modificação adicional — abra uma
issue descrevendo seu cenário.

## Instalação

```bash
git clone https://github.com/Vini20-foss/dns-authority-transition
cd dns-authority-transition
```

Edite `src/main.rs` e ajuste as duas constantes marcadas no topo do arquivo:

```rust
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1); // seu resolvedor local
const VPN_INTERFACE: &str = "SUBSTITUA_PELO_NOME_DA_SUA_INTERFACE";
```

Compile:

```bash
cargo build --release
```

**Teste manualmente antes de instalar em produção** — veja
[`TESTING.md`](TESTING.md) para um roteiro de testes incrementais
(modo `down` sem sudo, modo `down` com sudo, simulação do modo `up`,
verificação de fail-closed) que valida cada camada de proteção antes de
confiar o sistema à automação completa.

Instale:

```bash
sudo mkdir -p /usr/local/libexec
sudo install -o root -g root -m 750 target/release/dns-authority-transition \
    /usr/local/libexec/dns-authority-transition

sudo install -o root -g root -m 750 dispatcher/50-dns-authority-transition.sh \
    /etc/NetworkManager/dispatcher.d/50-dns-authority-transition.sh
```

### Reforço opcional recomendado: fs-verity

```bash
sudo pacman -S fsverity-utils   # ou o equivalente na sua distro
sudo fsverity enable /usr/local/libexec/dns-authority-transition
sudo fsverity enable /etc/NetworkManager/dispatcher.d/50-dns-authority-transition.sh
```

**Atenção:** isso torna os dois arquivos permanentemente somente-leitura.
Para atualizar no futuro, é necessário remover o arquivo e instalar uma
nova versão do zero — não existe "desabilitar" fs-verity em um arquivo já
habilitado.

## Limitações conhecidas

- `VPN_INTERFACE` é uma constante fixa em tempo de compilação, não um valor
  configurável em runtime. Trocar de VPN exige recompilar.
- Suporta apenas IPv4 hoje.
- Pressupõe que sua VPN é gerenciada via NetworkManager e expõe
  `IP4_NAMESERVERS` no ambiente do dispatcher — isso é verdade para muitos
  clientes comerciais, mas não é garantido universalmente.
- Testado em um único ambiente (ver "Status do projeto"). Reporte
  incompatibilidades via issues.

## Licença

MIT — veja [`LICENSE`](LICENSE).
