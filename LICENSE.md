# Licença — GNU General Public License v3.0

Este projeto é **software livre**, distribuído sob os termos da
**GNU General Public License, versão 3 (GPLv3)** ou, a critério do
usuário, qualquer versão posterior publicada pela Free Software Foundation.

Texto oficial e integral da licença: https://www.gnu.org/licenses/gpl-3.0.txt

Copyright (C) 2026 Pedro Rossi

---

## Por que GPLv3

Antes das cláusulas, uma nota de contexto. O Secure Commit é um projeto
educacional de ASPM que combina scanners open-source (Semgrep, Trivy,
Gitleaks, OWASP ZAP) com uma camada de IA. A GPLv3 foi escolhida de propósito:
ela é uma licença *copyleft forte*, o que significa que trabalhos derivados
também precisam ser livres. Em um projeto de segurança, isso importa — o
código que decide se um alerta é falso positivo, ou que sugere uma correção
pra uma vulnerabilidade, não deveria virar caixa-preta na mão de quem for
redistribuir. Quem recebe, repassa a mesma liberdade.

---

## As quatro liberdades (resumo das Seções 0–2 da GPLv3)

A GPL garante a qualquer pessoa que receba o programa:

- **Liberdade 0** — executar o programa para qualquer propósito.
- **Liberdade 1** — estudar como o programa funciona e adaptá-lo às suas
  necessidades. O acesso ao código-fonte é pré-condição.
- **Liberdade 2** — redistribuir cópias.
- **Liberdade 3** — distribuir cópias de versões modificadas, dando à
  comunidade a chance de se beneficiar das mudanças.

Nenhuma dessas liberdades depende de autorização do autor. Elas são
inerentes à licença.

---

## Obrigações de quem redistribui

Se você redistribuir este software — original ou modificado, em código
ou em binário — a GPLv3 te obriga a:

1. **Disponibilizar o código-fonte correspondente** (Seção 6). Não basta
   publicar o binário; o código que gerou aquele binário tem que estar
   acessível pela mesma rota, na mesma versão, pelo mesmo tempo.

2. **Manter os avisos de copyright e de licença** (Seção 5a). Inclua este
   arquivo `LICENSE.md` e os cabeçalhos de licença dos arquivos originais.

3. **Marcar modificações claramente** (Seção 5a). Se você mudou alguma
   coisa, deixe registrado — data e autor da modificação. Commit messages
   decentes resolvem isso.

4. **Licenciar o trabalho derivado também sob a GPLv3** (Seção 5c). Esse é
   o coração do *copyleft*: você não pode pegar código GPL, adicionar o
   seu, e redistribuir sob uma licença mais restritiva. O todo tem que
   permanecer livre.

5. **Não impor restrições adicionais** (Seção 10). Você não pode cobrar
   royalties sobre a licença em si, não pode exigir NDAs sobre o código,
   não pode usar DRM pra impedir que outros exerçam as liberdades da GPL.
   A GPLv3 trata explicitamente de *tivoização* — hardware que roda o
   software mas impede o usuário de modificá-lo — e proíbe esse padrão
   quando aplicável (Seção 6, parágrafo "User Product").

6. **Conceder a licença de patente embutida** (Seção 11). Quem contribui
   com código concede automaticamente uma licença de patente sobre as
   reivindicações necessárias para usar aquela contribuição. É a proteção
   anti-patent-troll que a v3 trouxe em relação à v2.

---

## Compatibilidade

A GPLv3 é compatível com:

- Apache License 2.0 (código Apache 2.0 pode ser incorporado a este projeto;
  o resultado é GPLv3).
- MIT, BSD-2-Clause, BSD-3-Clause, ISC (licenças permissivas são absorvidas
  pelo copyleft).
- LGPLv3 e AGPLv3 (famílias GPL compatíveis).

**Não é compatível com**: GPLv2-only (sem a cláusula "ou posterior"), e com
licenças proprietárias ou com restrições adicionais incompatíveis. Antes de
incorporar código de terceiros, verifique a licença de origem.

---

## Garantia e responsabilidade

Reprodução das Seções 15 e 16 da GPLv3, em tradução livre:

> **NÃO HÁ GARANTIA DE QUALQUER NATUREZA** para este programa, na extensão
> permitida pela lei aplicável. Exceto quando declarado por escrito pelos
> detentores de direitos autorais e/ou outras partes, o programa é fornecido
> "COMO ESTÁ", sem garantia de qualquer tipo, expressa ou implícita,
> incluindo mas não se limitando às garantias implícitas de
> COMERCIABILIDADE e ADEQUAÇÃO A UM PROPÓSITO ESPECÍFICO. Todo o risco
> quanto à qualidade e desempenho do programa é seu. Caso o programa se
> mostre defeituoso, você assume o custo de todo serviço, reparo ou correção
> necessários.

> Em nenhuma hipótese, exceto quando exigido por lei aplicável ou acordado
> por escrito, qualquer detentor de direitos autorais ou terceiro que
> modifique e/ou redistribua o programa conforme permitido acima será
> responsável perante você por danos, incluindo quaisquer danos gerais,
> especiais, incidentais ou consequenciais decorrentes do uso ou
> incapacidade de uso do programa.

Em caso de conflito entre esta tradução e o texto oficial da GPLv3 em
inglês, **o texto oficial prevalece**.

---

## Aviso específico do domínio

Este projeto executa ferramentas de segurança (scanners SAST, SCA, secret
scanning e DAST) e faz chamadas a LLMs externos (Anthropic Claude) para
triagem e sugestão de correção. O resultado dessas análises **não constitui
auditoria de segurança profissional** e não substitui revisão humana
qualificada. Antes de usar em produção, revise o código, entenda os limites
dos scanners, e trate o output da IA como insumo, não como veredito.

---

Pedro Rossi
