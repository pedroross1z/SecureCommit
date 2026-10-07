# Projeto: ASPM MVP com IA — Especificação para Claude Code

## Contexto e objetivo

Construir um **ASPM (Application Security Posture Management)** em versão MVP que usa a API da Anthropic como camada de inteligência em cima de scanners open source.

O sistema recebe a URL de um repositório GitHub e executa o ciclo completo:

```
descobre → coleta → correlaciona → prioriza → remedia → governa
```

O diferencial não é achar vulnerabilidade (scanner faz isso). É **reduzir ruído e dar contexto**: de 400 findings brutos, entregar 12 que importam, cada um com justificativa auditável e patch sugerido.

### Princípio de arquitetura inegociável

**A IA nunca produz fatos, só interpreta.** Scanner determinístico descobre; a IA classifica, correlaciona e prioriza. Toda saída de IA é gravada com `model`, `prompt_version`, `confidence` e `rationale` — se um analista discordar do score, ele precisa conseguir ver o porquê.

---

## Stack obrigatória

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 |
| Scanners | Semgrep, Trivy, Gitleaks (executados via subprocess em container) |
| Banco | PostgreSQL (Supabase) |
| Frontend | React 18 + Vite + TypeScript + TailwindCSS |
| IA | Anthropic API — `claude-haiku-4-5` (triagem) e `claude-sonnet-4-6` (análise profunda) |
| Jobs | FastAPI BackgroundTasks (não usar Celery no MVP) |
| Container | Docker + docker-compose |

Não introduzir dependências fora dessa lista sem necessidade real. Nada de LangChain, nada de vector DB, nada de ORM alternativo.

---

## Estrutura de pastas

```
aspm/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py              # settings via pydantic-settings
│   │   ├── db.py
│   │   ├── models/                # SQLAlchemy
│   │   ├── schemas/               # Pydantic (request/response + saídas de IA)
│   │   ├── api/
│   │   │   ├── assets.py
│   │   │   ├── scans.py
│   │   │   ├── findings.py
│   │   │   ├── remediation.py
│   │   │   └── policy.py
│   │   ├── core/
│   │   │   ├── discovery.py       # pilar 1
│   │   │   ├── collectors/        # pilar 2
│   │   │   │   ├── base.py
│   │   │   │   ├── semgrep.py
│   │   │   │   ├── trivy.py
│   │   │   │   └── gitleaks.py
│   │   │   ├── normalizer.py      # pilar 2
│   │   │   ├── correlator.py      # pilar 3
│   │   │   ├── prioritizer.py     # pilar 4
│   │   │   ├── remediator.py      # pilar 5
│   │   │   └── governance.py      # pilar 6
│   │   └── ai/
│   │       ├── client.py          # wrapper da API Anthropic
│   │       ├── prompts/           # cada prompt em .md versionado
│   │       └── cache.py
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/                 # Dashboard, AssetDetail, FindingDetail, Policy
│   │   ├── components/
│   │   └── lib/api.ts
│   └── package.json
├── policies/
│   └── default.yaml
├── docker-compose.yml
└── README.md
```

---

## Modelo de dados

Criar como migrations SQL em `backend/migrations/`.

```sql
-- Pilar 1: Descoberta
CREATE TABLE assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_url TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  default_branch TEXT,
  languages JSONB,              -- {"python": 0.7, "js": 0.3}
  frameworks JSONB,
  criticality SMALLINT,         -- 1..5, inferido por IA
  criticality_source TEXT,      -- 'ai' | 'manual'
  internet_facing BOOLEAN,
  handles_pii BOOLEAN,
  has_auth BOOLEAN,
  ai_rationale TEXT,
  owner TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  commit_sha TEXT,
  status TEXT NOT NULL,         -- queued|running|done|failed
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  tool_stats JSONB,             -- {"semgrep": {"findings": 120, "duration_s": 45}}
  error TEXT
);

-- Pilar 2: Coleta normalizada
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  source_tool TEXT NOT NULL,    -- semgrep|trivy|gitleaks
  category TEXT NOT NULL,       -- sast|sca|secret|iac|container
  rule_id TEXT,
  title TEXT NOT NULL,
  description TEXT,
  severity_raw TEXT,
  cwe TEXT[],
  cve TEXT,
  file_path TEXT,
  line_start INT,
  line_end INT,
  snippet TEXT,
  package_name TEXT,
  package_version TEXT,
  fixed_version TEXT,
  fingerprint TEXT NOT NULL,    -- dedup determinístico
  cluster_id UUID,              -- pilar 3
  status TEXT DEFAULT 'open',   -- open|triaged|false_positive|fixed|accepted_risk
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX ON findings (asset_id, fingerprint);

-- Pilar 3 e 4: enriquecimento por IA
CREATE TABLE ai_analysis (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
  reachability TEXT,            -- reachable|unreachable|unknown
  exploitability SMALLINT,      -- 1..5
  business_impact SMALLINT,     -- 1..5
  risk_score SMALLINT,          -- 0..100
  is_likely_false_positive BOOLEAN,
  confidence NUMERIC(3,2),      -- 0.00..1.00
  rationale TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  input_tokens INT,
  output_tokens INT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Pilar 5: Remediação
CREATE TABLE remediations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
  patch_diff TEXT,
  explanation TEXT,
  breaking_risk TEXT,           -- low|medium|high
  test_suggestion TEXT,
  applied BOOLEAN DEFAULT false,
  model TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Cache de IA por fingerprint (economia de custo)
CREATE TABLE ai_cache (
  cache_key TEXT PRIMARY KEY,   -- sha256(fingerprint + prompt_version)
  response JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
```

---

## Implementação por pilar

### Pilar 1 — Descoberta (`core/discovery.py`)

1. `git clone --depth 1` do repo em diretório temporário.
2. Detectar linguagens por extensão de arquivo e manifests (`requirements.txt`, `package.json`, `go.mod`, `pom.xml`).
3. Coletar sinais de contexto: README (primeiros 3000 chars), arquivos de rota/controller, Dockerfiles, IaC (`*.tf`, `docker-compose.yml`, manifests k8s), presença de libs de auth.
4. **Chamada de IA** (`claude-haiku-4-5`) recebe esses sinais e devolve JSON validado:

```json
{
  "service_type": "api|frontend|worker|library|cli",
  "criticality": 1,
  "internet_facing": true,
  "handles_pii": false,
  "has_auth": true,
  "rationale": "..."
}
```

Se o schema não validar, reprompt uma vez com o erro. Falhou de novo → grava `criticality_source='unknown'` e segue. **Nunca travar o pipeline por falha de IA.**

### Pilar 2 — Coleta (`core/collectors/`)

Interface comum em `base.py`:

```python
class Collector(Protocol):
    name: str
    category: str
    def run(self, repo_path: Path) -> list[RawFinding]: ...
```

Cada collector executa a ferramenta com saída JSON e faz parse:

- `semgrep --config auto --json --quiet`
- `trivy fs --format json --scanners vuln,misconfig,license`
- `gitleaks detect --report-format json --no-git`

Rodar os três **em paralelo** (`asyncio.gather` + `run_in_executor`). Timeout de 300s por ferramenta; se estourar, registrar em `scans.tool_stats` e continuar com os demais.

`normalizer.py` converte cada `RawFinding` para o schema unificado da tabela `findings`.

**Fingerprint** (determinístico, sem IA):

```python
fingerprint = sha256(
    f"{source_tool}|{rule_id}|{file_path}|{normalize_snippet(snippet)}|{cve or ''}"
)
```

`normalize_snippet` remove whitespace e nomes de variáveis locais, para o fingerprint sobreviver a refatorações cosméticas.

### Pilar 3 — Correlação (`core/correlator.py`)

Duas etapas, nessa ordem:

1. **Determinística (grátis):** agrupar por `cve` idêntico, ou por `(file_path, line_start)` com CWE compatível. Resolve a maioria.
2. **IA (só o resto):** para findings que sobraram no mesmo arquivo ou no mesmo pacote, mandar em lote de até 20 para `claude-haiku-4-5` decidir se compartilham causa raiz.

Saída esperada:
```json
{"clusters": [{"finding_ids": ["...", "..."], "root_cause": "...", "confidence": 0.85}]}
```

Um cluster vira uma linha só no dashboard, com contagem de ocorrências.

### Pilar 4 — Priorização (`core/prioritizer.py`)

O coração do sistema. Fluxo em dois estágios:

**Estágio 1 — triagem em lote (`claude-haiku-4-5`):** lotes de 20 findings + contexto do asset (criticidade, internet_facing, handles_pii). Devolve por finding: `reachability`, `exploitability`, `business_impact`, `is_likely_false_positive`, `confidence`, `rationale` curta.

**Estágio 2 — análise profunda (`claude-sonnet-4-6`):** só para findings que a triagem marcou como `exploitability >= 4` **ou** `confidence < 0.6`. Aqui manda-se o **arquivo completo** mais os arquivos que importam/chamam a função afetada. A pergunta central: *dado que entrada externa chega aqui, esse código é realmente explorável?*

**Score final — fórmula determinística, não pedir número pra IA:**

```python
risk_score = round(
    (exploitability * 0.35 + business_impact * 0.30 + reachability_weight * 0.35)
    * 20 * confidence
)
# reachability_weight: reachable=5, unknown=3, unreachable=1
```

Isso mantém o score auditável e comparável entre execuções. A IA fornece os fatores; a matemática é sua.

### Pilar 5 — Remediação (`core/remediator.py`)

Sob demanda (`POST /findings/{id}/remediate`), nunca automático. Usa `claude-sonnet-4-6` com o arquivo completo e devolve:

```json
{
  "patch_diff": "--- a/app/db.py\n+++ b/app/db.py\n@@ ...",
  "explanation": "...",
  "breaking_risk": "low",
  "test_suggestion": "..."
}
```

Validar que o diff aplica limpo com `git apply --check` antes de salvar. Se não aplicar, reprompt uma vez com o erro do git.

**O sistema nunca commita nem aplica patch sozinho.** Só exibe e oferece botão de copiar.

### Pilar 6 — Governança (`core/governance.py`)

`policies/default.yaml`:

```yaml
name: default
gates:
  - id: no-critical
    condition: "risk_score >= 85"
    max_allowed: 0
    action: block
  - id: secrets
    condition: "category == 'secret' and status == 'open'"
    max_allowed: 0
    action: block
  - id: high-budget
    condition: "risk_score >= 70"
    max_allowed: 5
    action: warn
```

Endpoint `POST /policy/evaluate/{scan_id}` retorna `{passed, violations[], summary}`. Um CLI `python -m app.cli gate --scan-id X` sai com exit code 1 se reprovar — é isso que entra no GitHub Actions.

O `summary` executivo (3 parágrafos, linguagem de negócio, sem jargão) é gerado por `claude-haiku-4-5`.

---

## Camada de IA (`app/ai/`)

Requisitos do wrapper em `client.py`:

1. **Toda chamada tem schema Pydantic de saída.** Instruir "responda apenas com JSON válido, sem markdown, sem preâmbulo". Fazer strip de cercas ` ```json ` antes do parse.
2. **Retry:** 1 tentativa de reprompt em falha de schema, incluindo a mensagem de erro do Pydantic. Depois disso, degrada graciosamente.
3. **Cache:** consultar `ai_cache` por `sha256(fingerprint + prompt_version)` antes de qualquer chamada.
4. **Prompts em arquivo:** `app/ai/prompts/*.md`, cada um com header `<!-- version: v1 -->`. Nunca prompt hardcoded em string Python.
5. **Telemetria:** logar tokens de entrada/saída e custo estimado por scan; expor em `GET /scans/{id}/ai-usage`.
6. **Rate limit:** semáforo de no máximo 5 chamadas concorrentes, backoff exponencial em 429.

---

## API

```
POST   /assets                      {repo_url} → cria asset e dispara discovery
GET    /assets                      lista com contagem de findings e score agregado
GET    /assets/{id}
POST   /assets/{id}/scan            dispara pipeline completo em background
GET    /scans/{id}                  status + tool_stats
GET    /scans/{id}/ai-usage
GET    /findings?asset_id=&min_score=&category=&status=
GET    /findings/{id}               inclui ai_analysis e cluster
PATCH  /findings/{id}               muda status (triaged/false_positive/accepted_risk)
POST   /findings/{id}/remediate     gera patch
POST   /policy/evaluate/{scan_id}
```

---

## Frontend

Quatro telas, sem firula:

1. **Dashboard** — cards de resumo (assets, findings abertos, score médio, ruído reduzido em %), tabela de assets ordenada por risco.
2. **Asset detail** — findings ordenados por `risk_score` desc, filtros por categoria e status, badge de cluster com contagem.
3. **Finding detail** — snippet com syntax highlight, o `rationale` da IA em destaque, breakdown do score (os três fatores), botão "Gerar correção" e ações de status.
4. **Policy** — resultado do gate, violações, resumo executivo.

Design: dark, denso, tipografia mono para código. Priorizar densidade de informação sobre espaço em branco — é ferramenta de analista, não landing page.

**Regra de UI:** todo dado gerado por IA precisa de indicador visual distinguindo-o de dado de scanner, e o `rationale` sempre visível junto ao score. Analista precisa saber o que é medição e o que é inferência.

---

## Ordem de implementação

Implementar em fases, **rodando e validando cada uma antes de seguir**:

| Fase | Entrega | Critério de aceite |
|---|---|---|
| 0 | Scaffold, docker-compose, migrations, health check | `docker compose up` sobe API + Postgres |
| 1 | Discovery + collectors + normalizer | Repo real gera N findings normalizados no banco |
| 2 | Correlação (determinística + IA) | Redução mensurável de contagem; clusters coerentes |
| 3 | Priorização 2 estágios + score | Todo finding tem `risk_score` e `rationale` |
| 4 | Remediação | Patch gerado passa em `git apply --check` |
| 5 | Frontend completo | Fluxo end-to-end pela UI |
| 6 | Policy engine + CLI gate + GitHub Action | Exit code correto em repo vulnerável |

Repo de teste sugerido para validação: qualquer projeto deliberadamente vulnerável tipo OWASP Juice Shop ou DVWA, que garante volume alto de findings.

---

## Restrições

- **Não** aplicar patches automaticamente, **não** commitar, **não** abrir PR sem ação explícita do usuário.
- **Não** enviar conteúdo de secrets encontrados para a API de IA — mandar apenas o padrão redigido (`AKIA****`), tipo do secret e localização.
- Falha de IA nunca derruba o pipeline: degradar para `unknown` e registrar.
- Todo endpoint com timeout explícito; nenhuma chamada de IA sem limite de tokens.
- Testes: cobrir normalizer, fingerprint e cálculo de score com pytest. Mockar a API de IA nos testes (nada de chamada real em CI).
- API key da Anthropic apenas via variável de ambiente, nunca em código ou commit.

---

## Comece por

Fase 0 e Fase 1 completas. Ao terminar, rode um scan real em um repositório vulnerável, mostre o output e o estado do banco antes de seguir para a Fase 2.
