# Roteiro de testes

Teste cada camada de forma incremental antes de instalar em produção. Não
pule etapas — cada uma valida uma garantia de segurança específica.

Pressupõe que você já compilou (`cargo build`, modo debug) e já ajustou
`VPN_INTERFACE`/`FALLBACK_DNS` em `src/main.rs`.

## 1. Confirmar suporte a Landlock no kernel

```bash
cat /sys/kernel/security/lsm
```

Deve listar `landlock` entre os LSMs ativos. Se não aparecer, o binário vai
se recusar a rodar (comportamento esperado, não é bug).

## 2. Testar sem privilégio (deve falhar, de propósito)

```bash
./target/debug/dns-authority-transition SEU_INTERFACE down
echo "código de saída: $?"
```

Esperado: falha com "Permission denied", código de saída `1`. Isso confirma
o comportamento fail-closed: sem root, o binário não consegue escrever, e
aborta sem deixar nada pela metade.

## 3. Testar modo `down` com privilégio (mais seguro: geralmente reafirma o valor já ativo)

```bash
sudo ./target/debug/dns-authority-transition SEU_INTERFACE down
echo "código de saída: $?"
cat /etc/resolv.conf
```

Esperado: código `0`, arquivo mostrando seu `FALLBACK_DNS`.

Confirme que a resolução DNS ainda funciona:

```bash
nslookup google.com
```

## 4. Simular o modo `up` manualmente, com um IP de teste controlado

```bash
sudo IP4_NAMESERVERS=10.2.0.1 ./target/debug/dns-authority-transition SEU_INTERFACE up
echo "código de saída: $?"
cat /etc/resolv.conf
```

**Atenção:** se sua VPN não estiver conectada neste momento, a resolução
DNS do sistema vai falhar temporariamente (o IP de teste não é roteável
sem o túnel ativo) — isso é esperado, não é um bug. Reverta imediatamente:

```bash
sudo ./target/debug/dns-authority-transition SEU_INTERFACE down
cat /etc/resolv.conf
nslookup google.com
```

## 5. Testar o toggle de imutabilidade

Depois de rodar o passo 3 (modo `down` com sucesso):

```bash
lsattr /etc/resolv.conf
```

Deve mostrar o atributo `i` ativo (`----i-----------------`).

Confirme que ninguém mais consegue escrever ali, nem root direto:

```bash
sudo bash -c 'echo "teste" >> /etc/resolv.conf'
```

Esperado: falha com "Operation not permitted", mesmo com sudo. Esta é a
prova de que a proteção de imutabilidade dinâmica está funcionando.

## 6. Instalar em produção e testar o ciclo completo

Só depois de validar os passos acima, compile em release e instale
seguindo o README. Depois, teste o ciclo real:

```bash
sudo journalctl -u NetworkManager-dispatcher.service -f
```

Em outra janela, desconecte e reconecte sua VPN pela interface normal.
Observe que nenhuma linha de erro do `dns-authority-transition` aparece
no log (silêncio = sucesso). Confirme o resultado:

```bash
cat /etc/resolv.conf
lsattr /etc/resolv.conf
nslookup google.com
```

Desconecte a VPN e confirme que volta sozinho para o `FALLBACK_DNS`, sem
qualquer comando manual.
