# Secure Commit — Deck para Canva (4 apresentadores)

> **Como usar este arquivo:** cada seção `## Slide N` = um slide no Canva.
> Copie o **título**, os **bullets** e use as **notas do apresentador** como roteiro (não colar no slide).
> **Design hints** = sugestão de layout/imagem para você aplicar no Canva.
> **Total: ~22 slides / ~25 min / 4 apresentadores.**

---

## Paleta e identidade visual (aplicar em todos os slides)

- **Cor primária:** azul-escuro (`#0F172A`) — fundo dos títulos
- **Cor destaque:** verde-lima (`#22D3EE` ou `#10B981`) — chamadas e "cadeado"
- **Cor alerta:** vermelho-coral (`#EF4444`) — usar em "problema" e "FAIL"
- **Fonte:** Inter, Poppins ou Montserrat (todas grátis no Canva)
- **Ícone recorrente:** cadeado com um `</>` dentro (representa código seguro)
- **Rodapé fixo:** logo "🔒 Secure Commit" + nome do grupo + data

---

# BLOCO 0 — Abertura (compartilhado)

## Slide 1 — Capa

**Título:** Secure Commit
**Subtítulo:** Segurança de código com IA, do commit ao deploy
**Rodapé:** [Nomes dos 4] · [Disciplina/Turma] · Ago 2026

**Design hints:**
- Fundo azul-escuro com um "cadeado + código" grande no centro
- Prompt Canva IA: *"Minimalist dark blue tech background with glowing padlock icon merged with source code brackets, cybersecurity, flat design"*

**Notas:** Quem abrir se apresenta rápido e apresenta os 4 nomes.

---

## Slide 2 — Agenda

**Título:** Agenda

**Bullets:**
- O problema — enxurrada de alertas de segurança
- A solução — Secure Commit em uma plataforma
- Como o scan acontece — 3 scanners orquestrados
- Inteligência Artificial — priorizar e corrigir
- Policy Engine + CI Gate — barrar código ruim
- Demo ao vivo
- Perguntas

**Design hints:** lista com ícones (lupa, engrenagem, cérebro, cadeado, terminal).

**Notas:** A pessoa 1 apresenta a agenda em 20s e passa para o próprio bloco.

---

# BLOCO 1 — Pessoa 1: Problema + Solução (~7 min)

## Slide 3 — A pergunta que dá o tom

**Título:** Quantas ferramentas de segurança uma empresa usa por dia?

**Bullets (revelar depois):**
- Empresa média: **20 a 50** ferramentas
- Cada uma gera alertas próprios
- Ninguém consegue ler tudo

**Design hints:**
- Slide quase vazio, só a pergunta gigante no meio
- Depois revelar "20 a 50" em vermelho grande

**Notas:** Pergunte pra plateia antes de mostrar a resposta. Pausa dramática.

---

## Slide 4 — Três tipos de risco, três ferramentas diferentes

**Título:** Risco vem de todo lado — e cada um exige uma ferramenta

**Bullets:**
- **Bug de lógica** — ex: SQL Injection → precisa de SAST
- **Senha vazada no código** — chave AWS commitada → precisa de Secret Scanner
- **Biblioteca desatualizada** — famoso Log4Shell (2021) → precisa de SCA
- Nenhuma conversa com a outra
- O dev vira "apagador de incêndio"

**Design hints:** três colunas com ícone (bug 🐛 / chave 🔑 / caixa 📦) e a ferramenta embaixo.

**Notas:** Explique o Log4Shell rápido — "uma linha em uma biblioteca abriu o mundo inteiro".

---

## Slide 5 — O resultado: fadiga de alertas

**Título:** Fadiga de alertas — o problema real

**Bullets:**
- Centenas de findings por scan
- 60-80% são falsos positivos ou baixo impacto
- Dev perde tempo → ignora tudo → o problema real passa

**Design hints:**
- Imagem: mesa cheia de post-its vermelhos, dev com a cabeça na mesa
- Prompt Canva IA: *"Overwhelmed developer at desk buried under red warning notifications, dark tones, illustration"*

**Notas:** "Segurança que ninguém lê é pior que segurança nenhuma — dá falsa sensação de controle."

---

## Slide 6 — Nossa solução

**Título:** Secure Commit — uma plataforma, um veredito

**Frase-chave (centralizada e grande):**
> Orquestra scanners open-source, prioriza com IA e bloqueia código ruim antes de entrar em produção.

**Bullets pequenos abaixo:**
- 3 scanners consagrados, de graça
- IA da Anthropic (Claude) prioriza e explica
- Portão automático no CI/CD

**Design hints:** grande, limpo, verde-lima na frase-chave. Cadeado no canto.

**Notas:** Esta é a "big idea". Deixe respirar. Não corra.

---

## Slide 7 — Arquitetura em alto nível

**Título:** Como as peças se encaixam

**Diagrama (desenhar no Canva com formas conectadas):**

```
[Repositório Git]
        ↓
[Semgrep] [Trivy] [Gitleaks]   ← scanners rodam em paralelo
        ↓
[Normalização + Correlação]     ← vira "Finding" único
        ↓
[IA: Haiku triage → Sonnet deep] ← prioriza e explica
        ↓
[Dashboard Web + CLI Gate no CI]
```

**Stack (canto inferior, fonte menor):**
FastAPI · React · PostgreSQL · Docker · Claude (Anthropic)

**Design hints:** setas grossas, cada bloco em um card retangular arredondado. Cores diferentes por camada.

**Notas:** Não leia cada caixinha — aponte o fluxo geral. "É um orquestrador, não reinventa scanner."

---

## Slide 8 — Passa a bola

**Título:** Agora, como um scan realmente acontece?

**Design hints:** slide de transição, curto. Foto ou avatar da Pessoa 2.

**Notas:** "Pra vocês entenderem o motor, quem vai contar é o(a) [Nome]."

---

# BLOCO 2 — Pessoa 2: Fluxo de scan (~5 min)

## Slide 9 — Passo 1: Discovery

**Título:** Passo 1 — Descoberta do repositório

**Bullets:**
- Usuário cola a URL do repo Git no dashboard
- Plataforma clona automaticamente
- Detecta linguagens e frameworks (Python, Django, Docker...)
- Cadastra como "asset" no banco

**Design hints:** screenshot da tela de "novo asset" ou mockup simples.

**Notas:** "Já temos um repositório real cadastrado: o PyGoat — projeto propositalmente vulnerável pra treino."

---

## Slide 10 — Passo 2: Três scanners em paralelo

**Título:** Passo 2 — Coletores rodam em paralelo

**Três colunas:**

| Semgrep | Trivy | Gitleaks |
|---|---|---|
| Padrões perigosos de código | Bibliotecas vulneráveis (CVEs) | Segredos vazados |
| Ex: `eval()` em Python | Ex: Django 4.2 → SQL Injection | Ex: `AWS_KEY=...` |

**Design hints:** cada scanner com sua marca/cor. Logos oficiais (Canva tem alguns).

**Notas:** "Escolhemos esses 3 porque são os melhores da categoria, gratuitos e maduros."

---

## Slide 11 — Passo 3: Normalização + Correlação

**Título:** Passo 3 — Tudo vira "Finding" e depois "Cluster"

**Bullets:**
- Cada scanner devolve JSON num formato diferente
- Nosso "normalizador" traduz tudo pra um esquema único: **título, severidade, arquivo, linha, categoria**
- **Fingerprint** (impressão digital) identifica findings iguais → agrupa em **cluster**
- Menos ruído na tela do dev

**Design hints:** três formas diferentes entrando num funil → uma forma única saindo → agrupadas em bolhas.

**Notas:** "Se 3 scanners apontam o mesmo problema, vira 1 item na tela — não 3."

---

## Slide 12 — Números reais do nosso MVP

**Título:** Rodamos no PyGoat — números reais

**Bullets destacados:**
- Semgrep: **0** findings (código customizado limpo)
- Gitleaks: **10** segredos expostos
- Trivy: **155** vulnerabilidades em dependências
- **Total: 163 findings** brutos → agrupáveis em dezenas de clusters
- Scan completo em **~50 segundos**

**Design hints:** números grandes, tipo "dashboard". Ícone de cronômetro no canto.

**Notas:** "Esses números são reais, rodados essa semana. Vocês vão ver na demo."

---

# BLOCO 3 — Pessoa 3: Inteligência Artificial (~5 min)

## Slide 13 — O problema que sobrou

**Título:** Mesmo depois de agrupar... qual atacar primeiro?

**Bullets:**
- Ainda temos dezenas de clusters
- Severidade "crítica" do scanner nem sempre é crítica no contexto
- Dev precisa de **prioridade explicável**, não de mais uma lista

**Design hints:** pilha de tickets, seta apontando "?".

**Notas:** Isso conecta com o bloco anterior — não é só filtrar, é entender o contexto.

---

## Slide 14 — Estratégia 2 estágios (economiza custo de IA)

**Título:** Priorização em 2 estágios

**Diagrama:**

```
Todos os findings
       ↓
[Claude HAIKU]        ← rápido, barato
Nota inicial 0-100
       ↓
Só os suspeitos
       ↓
[Claude SONNET]        ← lento, inteligente, lê o código em volta
Nota ajustada + rationale
```

**Bullets:**
- Haiku faz **triage** — filtra o óbvio
- Sonnet faz **análise profunda** — só do que importa
- Custo cai drasticamente vs. mandar tudo pro modelo caro

**Design hints:** duas caixas em cascata, cores diferentes (Haiku amarelo, Sonnet roxo).

**Notas:** "É a mesma lógica de triagem de hospital — não põe todo mundo direto no especialista."

---

## Slide 15 — Risk score explicável

**Título:** Cada finding ganha nota + explicação

**Exemplo (mockup de card):**
> **Django 4.2 — SQL Injection em `QuerySet.values()`**
> Risk Score: **87 / 100** 🔴
> **Rationale da IA:** "Esta versão do Django é usada em código de produção que expõe endpoints públicos com filtros dinâmicos. Vetor de ataque direto para exfiltração."
> `[Ver código] [Gerar correção]`

**Design hints:** mock de "card" bonito — arredondado, sombra, cor de severidade.

**Notas:** "A nota **explicável** é a chave. Não é caixa-preta — o dev sabe por quê."

---

## Slide 16 — Remediação sob demanda

**Título:** Um clique → correção pronta

**Bullets:**
- Botão "Gerar correção" chama o Sonnet de novo
- IA gera **unified diff** (formato Git universal)
- Também estima **breaking_risk** — "chance de quebrar algo"
- Dev revisa, aplica ou descarta — nunca aplica sozinho

**Design hints:** mock de diff colorido (vermelho `-`, verde `+`). Botão "Gerar" bem visível.

**Notas:** "É como um pair-programmer de segurança — sugere, você decide."

---

## Slide 17 — E se a IA errar?

**Título:** E se a IA errar?

**Bullets:**
- `breaking_risk` avisa quando a correção é arriscada
- Diff **nunca é aplicado sozinho** — dev revisa
- Rationale é auditável — dá pra contestar
- Findings de scanner + IA se complementam, não se substituem

**Design hints:** ícone de balança (equilíbrio) grande.

**Notas:** Pergunta comum de banca. Já responde antes de ser perguntada.

---

# BLOCO 4 — Pessoa 4: Policy Engine + CI Gate + DEMO (~7 min)

## Slide 18 — O elo final: automação no CI

**Título:** Dashboard bonito não basta

**Bullets:**
- Dev não vai abrir o dashboard todo dia
- Precisamos de um **portão automático** no pipeline
- Reprovar o Pull Request quando quebrar a política

**Design hints:** ilustração de "cancela" de pedágio bloqueando um "caminhão de código".

**Notas:** Ponte pro policy engine.

---

## Slide 19 — Policy Engine em YAML

**Título:** Cada empresa escreve as regras dela

**Bloco de código (fonte monoespaçada):**
```yaml
rules:
  - id: no-secrets
    action: fail        # reprova
    when:
      category_in: [secret]

  - id: ai-high-risk
    action: fail
    when:
      min_risk_score: 80
```

**Tradução (embaixo):**
> "Reprove se tiver segredo exposto OU se a IA deu nota ≥ 80."

**Design hints:** bloco de código estilizado (dark theme). Comentário em verde.

**Notas:** "YAML é texto — fica versionado no Git. Auditor lê fácil."

---

## Slide 20 — CI Gate (`aspm_gate.py`)

**Título:** Um script, um veredito

**Bloco de terminal:**
```bash
$ python aspm_gate.py --asset-id <UUID> --policy default

status : FAIL
  no-secrets       : 8 hits  🔴
  no-critical-cve  : 9 hits  🔴
  no-high-risk-cve : 61 hits 🔴

exit 1  → PR bloqueado
```

**Bullets:**
- `exit 0` = passa
- `exit 1` = reprova
- Plug-and-play com GitHub Actions, GitLab CI, Jenkins

**Design hints:** mock de terminal (fundo preto, texto verde/vermelho).

**Notas:** "Esses números são do nosso scan real do PyGoat. Vamos ver ao vivo agora."

---

## Slide 21 — DEMO AO VIVO

**Título:** Demo — Secure Commit em ação

**Roteiro (~2-3 min):**
1. Abrir `http://localhost:5173` — dashboard
2. Mostrar asset PyGoat, entrar, listar findings
3. Abrir 1 finding com risk_score alto — mostrar rationale da IA
4. Clicar em "Gerar correção" — mostrar diff
5. No terminal: rodar `aspm_gate.py` → mostrar `FAIL` colorido

**Design hints:** slide simples, praticamente só o título. Pode ter QR code apontando pro repo.

**Notas de segurança:** ter navegador já aberto na aba certa, terminal já com o comando digitado (só apertar Enter). **Testar 10 min antes.**

---

# BLOCO 5 — Encerramento

## Slide 22 — Recap

**Título:** Recapitulando

**Bullets:**
- **Problema:** enxurrada de alertas → fadiga → risco real ignorado
- **Solução:** orquestrador de scanners + IA que prioriza + gate no CI
- **Resultado:** dev vê poucos itens, todos relevantes, com sugestão de correção
- **Estado:** MVP funcional, 6 fases entregues, 49 testes passando

**Design hints:** 4 cards curtos lado a lado, cada um com ícone.

**Notas:** Fechamento — quem falar aqui pode ser qualquer um. Recomendado a Pessoa 1 pra "amarrar".

---

## Slide 23 — Próximos passos (fora do MVP)

**Título:** O que ainda queremos fazer

**Bullets:**
- Autenticação e multi-usuário
- Integração nativa com GitHub Actions (Marketplace)
- Suporte a mais linguagens (Rust, Swift, Kotlin)
- Dashboard de tendências (findings ao longo do tempo)
- SBOM e conformidade (LGPD, SOC 2)

**Design hints:** roadmap horizontal com marcos.

**Notas:** Mostra maturidade — vocês sabem o que falta.

---

## Slide 24 — Obrigado + Perguntas

**Título:** Obrigado! Perguntas?

**Rodapé:**
- Nomes dos 4 apresentadores
- Email/GitHub (se tiver)
- QR code do repo (opcional)

**Design hints:** grande, limpo, cadeado central. Fundo escuro.

**Notas:** Deixe 2-3 min pra perguntas. Divida entre os 4 quem responde qual tema:
- Problema/produto → Pessoa 1
- Arquitetura/scan → Pessoa 2
- IA/Claude → Pessoa 3
- Policy/DevOps → Pessoa 4

---

# Anexo — Perguntas prováveis da banca (deixem estudado)

| Pergunta | Quem responde | Resposta curta |
|---|---|---|
| Por que não usar Snyk/SonarQube pago? | P1 | Custo alto por dev/mês, caixa-preta, e a gente cobre o mesmo com 3 open + IA. |
| Por que Python no backend? | P2 | Ecossistema de segurança maduro (Semgrep é Python), FastAPI é um dos mais rápidos. |
| Como sabem que 2 achados são o mesmo? | P2 | Fingerprint (hash) de: tool + rule + arquivo + linha. |
| E se a IA alucinar? | P3 | Diff não é aplicado sozinho, breaking_risk avisa, rationale é auditável. |
| Quanto custa em API da Anthropic? | P3 | Haiku triage é centavos por scan; Sonnet só nos suspeitos. Estimamos < US$ 0,10 por scan. |
| Roda em qualquer linguagem? | P4 | Sim — scanners cobrem Python, JS/TS, Java, Go, Ruby, C#, Docker, IaC. |
| Como funciona em pipeline real? | P4 | Um passo no GitHub Actions chama `aspm_gate.py`; exit 1 bloqueia o merge. |

---

# Anexo — Checklist do dia da apresentação

- [ ] Notebook carregado, cabo de energia junto
- [ ] Backend rodando em `localhost:8000` (testar `/health` antes)
- [ ] Frontend rodando em `localhost:5173`
- [ ] Terminal aberto com comando `aspm_gate.py` pronto (só apertar Enter)
- [ ] Navegador com abas: dashboard, 1 finding específico já aberto
- [ ] Chave `ANTHROPIC_API_KEY` válida no `.env` (**rotacionar antes se o zip for compartilhado**)
- [ ] Deck aberto em tela cheia
- [ ] Testar projeção 10 min antes
- [ ] Cronometrar em ensaio (~25 min total)
