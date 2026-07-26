# Política de Segurança

Obrigado por se preocupar com a segurança deste projeto. Este documento descreve como reportar vulnerabilidades, como tratamos os relatórios e quais prazos você pode esperar.

## Escopo

Esta política aplica-se a este repositório (dns-authority-transition) e ao código publicado aqui. Ela não cobre dependências de terceiros — vulnerabilidades nessas dependências devem ser reportadas aos mantenedores dessas dependências, embora nós possamos publicar correções ou mitigação quando aplicável.

## Versões suportadas

Atualmente este repositório não mantém versões distribuídas formalmente; o código principal é mantido na branch `main`. Se você usar uma release/tags específicas, reporte a versão/tags que está afetada.

Se o projeto passar a ter releases/branches com suporte formal, atualizaremos esta seção com a tabela de versões suportadas e o ciclo de suporte.

## Como reportar uma vulnerabilidade (preferências)

1. Prefira abrir um GitHub Security Advisory privado no repositório: https://github.com/OWNER/REPO/security/advisories (substitua OWNER/REPO por `Vini20-foss/dns-authority-transition`).
2. Se não puder usar a advisory do GitHub, envie um e-mail para: security@vini20-foss.dev (substitua por um e-mail válido do mantenedor) com o assunto: [SECURITY] dns-authority-transition — <breve descrição>
3. Se você precisa enviar detalhes sensíveis (proof-of-concept, exploit), use criptografia PGP. Adicione aqui a chave pública PGP dos mantenedores quando disponível.

Por favor inclua nas comunicações:
- Descrição clara do problema (passos para reproduzir).
- Versão/commit/branch afetada.
- Impacto esperado (confidencialidade, integridade, disponibilidade).
- Provas de conceito (se seguro) e como reproduzir.
- Seu contato para follow-up (e-mail ou X/Otra forma).

## O que esperar após o envio

- Confirmação de recebimento: em até 3 dias úteis.
- Triage inicial: em até 7 dias úteis, confirmaremos se o relatório é duplicado, válido, e atribuiremos severidade.
- Plano de correção: para vulnerabilidades críticas, buscaremos uma correção ou mitigação imediata e comunicaremos um cronograma. Para outras severidades, procuraremos publicar uma correção dentro do prazo razoável descrito abaixo.

Prazos orientativos por severidade:
- Crítico: mitigação/patch em até 7 dias (ou antes, quando possível).
- Alto: patch em até 30 dias.
- Médio: patch em até 90 dias.
- Baixo: patch em até 180 dias ou catalogação para futuras melhorias.

Esses prazos são metas e podem variar dependendo da complexidade, disponibilidade de recursos e coordenação com terceiros.

## Divulgações coordenadas

Por favor, não publique detalhes públicos da vulnerabilidade até que um patch esteja disponível ou tenhamos acordado divulgação coordenada. Nós trabalharemos com o reportante para coordenar a divulgação responsável e, quando apropriado, atribuir/solicitar um CVE.

## Incentivo e agradecimento

Agradecemos contribuições responsáveis de segurança. Se desejar um reconhecimento público (nome na lista de agradecimentos), indique isso quando reportar.

## Contato e PGP

- GitHub Security Advisory (preferido): https://github.com/Vini20-foss/dns-authority-transition/security/advisories
- E-mail de contato (substitua por um e-mail válido do mantenedor se desejar): security@vini20-foss.dev
- Chave PGP pública: (ainda não configurada) — envie uma chave pública ou peça instruções para criptografar a submissão.

---

Se quiser, eu atualizo o e-mail de contato ou adiciono a chave PGP pública aqui — diga qual e-mail/PGP usar que eu aplico a mudança e commito o arquivo.
