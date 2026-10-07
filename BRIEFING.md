# Briefing — Secure Commit

> Roteiro pra apresentacao em grupo de **4 pessoas** (~25 min total, ~5-7 min cada).
> Linguagem simples, direta. Termos tecnicos aparecem com uma explicacao curta na primeira vez.

---

## Elevator pitch (1 frase)

**Secure Commit e um cao de guarda de codigo com IA: le seu repositorio, aponta so o que importa e bloqueia o merge quando algo grave passar.**

## Contexto rapido

Todo time de desenvolvimento hoje usa varias ferramentas de seguranca. Uma acha bug de codigo, outra acha senha vazada, outra acha biblioteca desatualizada. O resultado e uma **enxurrada de alertas**, muito falso alarme, sem prioridade clara. O dev acaba ignorando tudo e o problema real passa.

Secure Commit resolve isso: roda **3 scanners open-source de graca**, junta os resultados num relatorio unico, usa a **IA da Anthropic (Claude)** pra dar nota de risco e ate sugerir a correcao, e disponibiliza um **portao automatico** que reprova codigo ruim no CI/CD.

## O que ja esta pronto

MVP completo em 6 fases:
1. Base tecnica (API + banco + Docker)
2. Descoberta de repositorio + 3 scanners + relatorio unificado
3. Agrupamento de alertas parecidos (menos ruido)
4. IA priorizando o que importa
5. IA sugerindo a correcao
6. Portal web + regras em YAML + script pra rodar no CI

**49 testes automatizados, todos passando.**

---

# Divisao para 4 apresentadores

---

## Pessoa 1 — Problema + Solucao (~7 min)

**Objetivo:** deixar claro que **existe uma dor real** e mostrar como a gente resolve.

### Roteiro

**Parte A - o problema (~3 min)**

- Pergunta pra plateia: *"quantas ferramentas de seguranca voces acham que uma empresa grande usa por dia?"* — resposta comum: 20 a 50.
- Cada tipo de risco exige uma ferramenta diferente:
  - **Bug de logica** — atacante explora falha do codigo pra roubar dados
  - **Senha vazada** — chave da AWS esquecida dentro do codigo
  - **Biblioteca desatualizada** — o famoso Log4Shell de 2021, uma linha em uma biblioteca abriu o mundo inteiro
- Cada ferramenta grita separado. Ninguem conversa com ninguem. Dev vira apagador de incendio.
- Resultado: **fadiga de alerta**. Segurança que ninguem le e pior que nenhuma — da falsa sensacao de controle.

**Parte B - a solucao (~4 min)**

- Secure Commit e uma **plataforma unica** que junta tudo:
  - Roda 3 scanners de graca em paralelo (proxima pessoa detalha)
  - Junta e agrupa os alertas
  - IA prioriza o que importa e explica o porque
  - Portal web pro time visualizar
  - **Portao automatico** no CI/CD que reprova o codigo ruim antes do merge
- Stack, sem entrar em detalhe: Python no servidor, React no site, Docker pra rodar, IA da Anthropic.
- **Zero lock-in**: os scanners sao open-source, IA pode ser trocada.

### Termos

- **AppSec** *(Application Security)*: area que cuida da seguranca dentro do proprio codigo
- **Falso positivo**: alerta que a ferramenta gerou mas nao e problema real
- **CI/CD**: esteira automatica que testa e publica o codigo quando alguem faz push

### Perguntas provaveis

> *"Por que nao usar so uma ferramenta paga completa (Snyk, Checkmarx)?"*
Custam **dezenas de milhares de reais por ano por time**, sao caixa-preta e nem sempre integram bem. Com 3 gratuitas + IA a gente cobre o mesmo pagando so o uso da API — centavos por scan.

> *"Por que Python?"*
Ecossistema de seguranca e Python (Semgrep e escrito em Python), bibliotecas de IA maduras.

---

## Pessoa 2 — Como o scan acontece (~5 min)

**Objetivo:** contar a **historia de um scan** e apresentar as 3 ferramentas.

### Roteiro

**Passo 1 - Descoberta**
- Usuario cola URL do repositorio no portal
- Plataforma clona o codigo automaticamente
- Detecta linguagens e frameworks

**Passo 2 - As 3 ferramentas (o coracao do scan)**

**Semgrep** — o revisor de codigo
> Le o codigo que **seu time escreveu** procurando padroes perigosos. Como um professor de portugues que passa o olho e circula os erros de gramatica — so que aqui os "erros" sao coisas tipo campo de busca vulneravel a hacker, senha aparecendo em log.

**Trivy** — o conferente de estoque
> Todo software moderno usa dezenas de **bibliotecas prontas** de terceiros. Trivy pega essa lista, compara com um banco publico de vulnerabilidades e avisa: "essa versao do Django tem brecha, atualiza". Tambem olha configuracao de Docker.

**Gitleaks** — o detector de vazamento
> Vasculha o codigo atras de **coisas que nunca deviam estar ali**: senhas, chaves de API, tokens da AWS. E o erro mais comum e mais perigoso — dev poe a chave pra testar, esquece, sobe pro GitHub, hacker acha em minutos.

- As 3 rodam **ao mesmo tempo** — o scan nao espera uma pela outra.

**Passo 3 - Juntar tudo**
- Cada scanner devolve resultado num formato diferente
- A plataforma traduz tudo pra um relatorio **unico**
- Alertas iguais viram **1 so** (menos ruido pro dev)

**Numeros reais do nosso teste (PyGoat, projeto propositalmente vulneravel):**
- Semgrep: 0 alertas
- Gitleaks: **10** segredos expostos
- Trivy: **155** bibliotecas com falha
- **Total: 163 alertas em ~50 segundos**

### Termos

- **CVE** *(Common Vulnerabilities and Exposures)*: id publico de uma vulnerabilidade conhecida (ex: `CVE-2021-44228` = Log4Shell)
- **Severidade**: quao grave (`low`, `medium`, `high`, `critical`)

### Perguntas provaveis

> *"Por que essas 3 e nao outras?"*
Sao gratuitas, as mais usadas do mercado na categoria, e juntas cobrem as 3 fontes principais de risco: codigo proprio, codigo de terceiros e segredos vazados.

> *"Como sabem que 2 alertas sao o mesmo problema?"*
Cada alerta ganha uma "impressao digital" baseada em: tipo + arquivo + linha + regra. Se bate igual, e o mesmo problema.

---

## Pessoa 3 — Inteligencia Artificial (~5 min)

**Objetivo:** mostrar **onde a IA entra** e por que ela e o diferencial.

### Roteiro

**O problema que sobra**
- Mesmo depois de agrupar, sobram dezenas de alertas
- Qual atacar primeiro? Severidade "critica" nem sempre e critica no seu contexto
- Dev precisa de **prioridade explicavel**, nao de mais uma lista

**A IA faz 2 coisas:**

**1. Prioriza os alertas (com 2 modelos diferentes)**

Rodar IA em todo alerta sairia caro. Entao usamos **estrategia em 2 estagios**:

- **Claude Haiku** (rapido e barato) — le todos os alertas e da uma nota inicial de 0 a 100
- **Claude Sonnet** (mais forte, mais caro) — so os suspeitos passam por ele, que le o codigo em volta e ajusta a nota

Resultado: cada alerta ganha `risk_score` de 0 a 100 **explicavel** — o dev ve por que a IA achou grave.

**Custo tipico por scan: menos de 10 centavos de dolar.**

**2. Sugere a correcao (sob demanda)**

- Dev clica em "gerar correcao"
- Sonnet le o codigo e devolve o conserto pronto (formato `diff` — mostra o que remove e o que adiciona)
- Junto vem `breaking_risk` — chance daquela correcao quebrar algo
- **Nunca aplica sozinho** — dev revisa e decide

Compara com um *pair programmer* de seguranca: sugere, voce decide.

### Termos

- **LLM** *(Large Language Model)*: IA que le e escreve texto (Claude, ChatGPT)
- **Diff**: mostra o que muda no codigo — linhas com `-` (removidas) e `+` (adicionadas)

### Perguntas provaveis

> *"E se a IA errar / alucinar?"*
Duas protecoes: (1) `breaking_risk` avisa quando a correcao e arriscada; (2) o diff **nunca e aplicado sozinho** — dev revisa. Alem disso, o `risk_score` vem com explicacao auditavel.

> *"Quanto custa em API?"*
Menos de 10 centavos de dolar por scan. Estagio Haiku (triagem) e centavos, Sonnet (analise profunda) so nos casos suspeitos.

---

## Pessoa 4 — Portao no CI + Demo ao vivo (~7 min)

**Objetivo:** mostrar como o Secure Commit **efetivamente bloqueia codigo ruim**, e fazer a **demonstracao**.

### Roteiro

**Parte A - o portao (~3 min)**

- Ter dashboard bonito e legal, mas nao adianta se o dev ignorar
- Precisamos de um **portao automatico** no pipeline

**Como funciona:**
- Cada empresa escreve as **regras dela em YAML** (arquivo texto simples). Exemplo:

```yaml
- id: no-secrets
  action: fail       # reprova
  when:
    category_in: [secret]

- id: ai-high-risk
  action: fail
  when:
    min_risk_score: 80
```

- Traducao: **"reprove se tiver senha exposta OU se a IA deu nota >= 80"**
- Um script (`aspm_gate.py`) roda no CI/CD:
  - `exit 0` = merge liberado
  - `exit 1` = merge bloqueado
- Plug-and-play com GitHub Actions, GitLab CI, Jenkins

**Parte B - demo ao vivo (~4 min)**

Roteiro:
1. Abrir `http://localhost:5173` — mostrar o dashboard
2. Entrar no asset PyGoat, mostrar a lista de alertas
3. Abrir 1 alerta com nota alta — **mostrar a explicacao da IA**
4. Clicar em "gerar correcao" — mostrar o diff colorido
5. No terminal, rodar o gate: `python aspm_gate.py --asset-id ... --policy default`
6. Mostrar o resultado: **FAIL — 8 secrets + 9 criticos + 61 CVEs de alto risco**

**Encerramento (30s)**
- Secure Commit **transforma seguranca em rotina de codigo**, nao em auditoria depois do fato
- Proximos passos fora do MVP: autenticacao de usuario, integracao nativa com GitHub Actions, suporte a mais linguagens

### Termos

- **Gate**: portao automatico que aprova ou reprova um Pull Request
- **Pull Request (PR)**: pedido de merge — dev abre pra fundir a mudanca dele na branch principal

### Perguntas provaveis

> *"Roda em qualquer linguagem?"*
Sim. Os 3 scanners cobrem Python, JavaScript, TypeScript, Java, Go, Ruby, C#, Docker, YAML, Terraform. A camada de IA e agnostica.

> *"Como integra com GitHub Actions?"*
E so 1 passo no arquivo `.github/workflows/`: chamar `aspm_gate.py`. Se retornar `exit 1`, o GitHub bloqueia o merge automaticamente.

---

# Anexo — Como rodar no dia da apresentacao

**Modo rapido:** clique duplo nos `.bat` em `D:\ASPM\` na ordem:
1. `01-backend-start-fastapi-porta-8000.bat`
2. `02-frontend-start-vite-porta-5173.bat`
3. `03-check-saude-backend-e-frontend.bat` (verificacao)
4. `04-demo-rodar-ci-gate-pygoat.bat` (**so na hora da demo**)

Se travar porta: `05-fix-matar-processos-travados.bat` e volta pro 1.

Ver `COMO_RODAR.md` pra detalhes, backup e plano B.

---

# Glossario rapido

| Termo | Traducao "de bolso" |
|---|---|
| AppSec | Seguranca aplicada ao codigo, antes de virar produto |
| Scanner | Programa que le codigo procurando problemas |
| Finding / Alerta | Um problema encontrado |
| Cluster | Grupo de alertas iguais/parecidos |
| CVE | Id de uma vulnerabilidade publica conhecida |
| CI/CD | Esteira que testa e publica automaticamente |
| Gate | Portao automatico que aprova ou reprova um PR |
| Pull Request | Pedido de merge |
| LLM | Modelo de IA que le e escreve texto (Claude, ChatGPT) |
| Diff | Mostra o que muda no codigo (linhas `-` e `+`) |
| Falso positivo | Alerta que nao e problema real |
