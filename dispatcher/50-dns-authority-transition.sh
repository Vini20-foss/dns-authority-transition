#!/bin/bash
# Wrapper de dispatcher do NetworkManager.
#
# Propositalmente sem lógica: toda decisão (qual interface reconhecer,
# o que escrever, validação de valores) vive no binário Rust, que roda
# sob sandbox Landlock. Este script existe apenas porque o mecanismo de
# dispatcher do NetworkManager espera um script executável, não aceita
# um binário ELF registrado diretamente.
#
# Instale em: /etc/NetworkManager/dispatcher.d/50-dns-authority-transition.sh
# Permissões: chmod 750, dono root:root
#
# "$1" = nome da interface, "$2" = ação (up/down/etc.)
# O ambiente (incluindo IP4_NAMESERVERS) é herdado automaticamente pelo
# processo filho — não precisa ser repassado explicitamente.

exec /usr/local/libexec/dns-authority-transition "$1" "$2"
