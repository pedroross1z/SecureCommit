# Secure Commit — Sobre o Projeto

> MVP de **ASPM** (Application Security Posture Management) que orquestra scanners open-source, correlaciona findings e usa IA da Anthropic para priorizar e sugerir correções.

---

## 1. Visão geral

**Secure Commit** é uma plataforma única que resolve a dor da **fadiga de alerta** em segurança de aplicação: times modernos usam dezenas de ferramentas (SAST, SCA, secret scanning) que gritam separado, não conversam entre si, e enterram o desenvolvedor em falsos positivos.

A proposta é simples:

1. Rodar **3 scanners open-source** em paralelo (Semgrep + Trivy + Gitleaks).
2. **Normalizar** os resultados em um único formato.
3. **Agrupar** alertas duplicados em clusters (menos ruído).
4. Usar **IA da Anthropic (Claude)** em 2 estágios para priorizar o que importa.
5. Oferecer **remediação sob demanda** (diff pronto + risco de quebra).
6. Expor um **portão (gate) automático no CI/CD** que reprova PRs via regras em YAML.

**Zero lock-in:** scanners são gratuitos, a camada de IA é agnóstica (pode trocar o provider).

---

## 2. Arquitetura

```
┌─────────────┐    ┌──────────────────────────────────────────┐    ┌──────────────┐
│  Frontend   │ ─► │  Backend FastAPI                         │ ─► │  PostgreSQL  │
│  React + TS │    │  - discovery / collectors / normalizer   │    │  (SQLite dev)│
│  Vite       │    │  - correlator (clusters)                 │    └──────────────┘
└─────────────┘    │  - IA (Haiku triage + Sonnet deep)       │
                   │  - policy engine (YAML)                  │    ┌──────────────┐
                   └──────────────────────────────────────────┘ ─► │  Anthropic   │
                                       │                           │  Claude API  │
                                       ▼                           └──────────────┘
                   ┌──────────────────────────────────────────┐
                   │  CLI gate (aspm_gate.py) → exit 0/1 no CI│
                   └──────────────────────────────────────────┘
```

### Fluxo de um scan

1. Usuário cola a URL de um repositório no portal (ex.: PyGoat).
2. Backend clona o código, detecta linguagens/frameworks.
3. Os 3 scanners rodam **em paralelo** no mesmo workdir.
4. O normalizer traduz cada saída (SARIF, JSON próprio) para o schema único de `Finding`.
5. O correlator agrupa findings por "impressão digital" (tipo + arquivo + linha + regra) em **clusters**.
6. A IA entra em 2 estágios:
   - **Haiku** varre todos os clusters e dá uma nota inicial (0–100).
   - **Sonnet** aprofunda apenas os suspeitos, lendo o código em volta.
7. O resultado — `risk_score` explicável — fica disponível na API/dashboard.
8. Dev pode clicar em "gerar correção" → Sonnet devolve um `diff` + `breaking_risk`.
9. No CI, o `aspm_gate.py` avalia o scan contra uma policy YAML e devolve `exit 0` (pass) ou `exit 1` (fail).

---

## 3. Stack técnico

### Backend
- **Python 3.11+**
- **FastAPI 0.115** — framework web assíncrono, docs OpenAPI automáticas em `/docs`
- **Uvicorn** — ASGI server
- **SQLAlchemy 2.0** — ORM
- **Pydantic v2 + pydantic-settings** — validação de schemas e config via env
- **PostgreSQL 16** (produção/compose) / **SQLite** (dev local)
- **anthropic 0.42** — SDK oficial do Claude
- **PyYAML** — carga das policies
- **httpx** — cliente HTTP para o gate
- **pytest** — 49 testes automatizados passando

### Frontend
- **React 18 + TypeScript 5**
- **Vite 5** — bundler/dev server (porta 5173)
- **TailwindCSS 3** — estilização utilitária
- **React Router 6** — navegação SPA
- **TanStack React Query 5** — cache e sincronização com a API
- **react-diff-viewer-continued** — visualização colorida dos diffs de remediação

### Infra / tooling
- **Docker + docker-compose** — sobe backend + Postgres com um comando
- **Scripts `.bat`** em `D:\ASPM\` para subir backend/frontend no Windows sem fricção
- Volume `scan_workdir` para repositórios clonados pelos scanners

---

## 4. Scanners open-source orquestrados

| Scanner | O que faz | Fonte do risco |
|---|---|---|
| **Semgrep** | SAST — lê o código do próprio time procurando padrões perigosos (SQL injection, XSS, logs com dados sensíveis, etc.) | Código próprio |
| **Trivy** | SCA + IaC — compara as bibliotecas de terceiros com um banco público de CVEs; também analisa Dockerfile e configs | Dependências e infra |
| **Gitleaks** | Secret scanning — varre o repositório atrás de chaves de API, tokens AWS, senhas commitadas | Segredos vazados |

**Por que esses três:** cobrem as 3 fontes principais de risco (código próprio, código de terceiros, segredos), são gratuitos, maduros e amplamente adotados no mercado.

**Resultado real no PyGoat** (projeto propositalmente vulnerável, usado como alvo de demo):
- Semgrep: 0 findings
- Gitleaks: **10 segredos** expostos
- Trivy: **155 CVEs** em bibliotecas
- **Total: 163 findings em ~50 segundos**

---

## 5. Camada de IA (Claude)

A IA é o diferencial que transforma uma lista crua de 163 alertas em prioridade acionável.

### Estratégia de 2 estágios (custo baixo)

| Estágio | Modelo | Quando | Papel |
|---|---|---|---|
| **Triagem** | `claude-haiku-4-5` | Em todos os clusters | Nota inicial de 0–100, rápida e barata |
| **Análise profunda** | `claude-sonnet-4-6` | Só nos suspeitos (nota alta) | Lê o código em volta, ajusta a nota, gera a explicação detalhada |

Cada finding sai com `risk_score` + justificativa auditável — o dev vê **por que** a IA achou grave.

**Custo típico por scan: < US$ 0,10.**

### Remediação sob demanda

Quando o dev clica em "gerar correção":
- Sonnet lê o código vulnerável e devolve um **unified diff** pronto
- Junto vem um `breaking_risk` (chance de quebrar comportamento existente)
- A correção **nunca é aplicada sozinha** — dev revisa, decide, faz merge

Comparação mental: um *pair programmer* de segurança que sugere, mas não comita por você.

---

## 6. Policy engine + CI gate

### Policies em YAML

Cada time escreve as regras em `policies/*.yaml`. Exemplo real de `policies/default.yaml`:

```yaml
rules:
  - id: no-secrets
    action: fail
    when:
      category_in: [secret]

  - id: no-critical-severity
    action: fail
    when:
      severity_in: [critical]

  - id: ai-high-risk
    action: fail
    when:
      min_risk_score: 80

  - id: warn-high-severity
    action: warn
    when:
      severity_in: [high]
```

Tradução: **reprova** se tiver secret exposto, finding crítico, CVE high+known ou nota da IA ≥ 80.

### CLI gate (`aspm_gate.py`)

Rodado dentro de GitHub Actions / GitLab CI / Jenkins:

```bash
python backend/bin/aspm_gate.py \
  --api-url http://localhost:8000 \
  --asset-id <UUID> \
  --policy default \
  --wait
```

- `exit 0` → merge liberado
- `exit 1` → merge bloqueado (regra `fail` violada)
- `exit 2` → erro operacional

Plug-and-play: um único step no workflow do CI.

---

## 7. Estrutura de pastas

```
D:\ASPM\
├── BRIEFING.md                 # roteiro de apresentação (4 pessoas, ~25 min)
├── COMO_RODAR.md               # instruções operacionais
├── SLIDES_CANVA.md             # material de slides
├── SOBRE_O_PROJETO.md          # este arquivo
├── 01..05-*.bat                # scripts Windows pra subir/matar os serviços
├── aspm/
│   ├── docker-compose.yml      # Postgres + backend
│   ├── backend/
│   │   ├── app/
│   │   │   ├── api/            # routers FastAPI (assets, scans, findings, clusters, remediations)
│   │   │   ├── core/           # discovery, collectors, normalizer, correlator, policy engine
│   │   │   ├── ai/             # cliente Claude + prompts (Haiku + Sonnet)
│   │   │   ├── models/         # SQLAlchemy
│   │   │   ├── schemas/        # Pydantic
│   │   │   ├── db.py / config.py / main.py
│   │   ├── bin/aspm_gate.py    # CLI para CI
│   │   ├── migrations/         # SQL init do Postgres
│   │   ├── tests/              # pytest (49 testes)
│   │   └── requirements.txt
│   ├── frontend/
│   │   └── src/                # React + TS (pages, components, hooks, router)
│   └── policies/
│       └── default.yaml
└── scan_workdir/               # volume compartilhado para clones dos scanners
```

---

## 8. Fases do MVP (todas concluídas)

| Fase | Entrega |
|---|---|
| 0 | Scaffold, docker-compose, migrations, health check |
| 1 | Discovery + 3 collectors (Semgrep/Trivy/Gitleaks) + normalizer + API assets/scans/findings |
| 2 | Correlação em clusters (menos ruído) |
| 3 | Priorização 2 estágios (Haiku triage + Sonnet deep) + `risk_score` |
| 4 | Remediação sob demanda (unified diff + breaking_risk) |
| 5 | Frontend SPA (Vite + React + TS + Tailwind) |
| 6 | Policy engine YAML + CLI gate para CI |

---

## 9. Como rodar

### Modo rápido (Windows)
Clique duplo nos `.bat` em `D:\ASPM\` nesta ordem:
1. `01-backend-start-fastapi-porta-8000.bat`
2. `02-frontend-start-vite-porta-5173.bat`
3. `03-check-saude-backend-e-frontend.bat`
4. `04-demo-rodar-ci-gate-pygoat.bat` *(só na hora da demo)*

Se travar porta: `05-fix-matar-processos-travados.bat` e volta ao 1.

### Modo Docker
```bash
cd aspm
cp .env.example .env   # ajuste ANTHROPIC_API_KEY
docker compose up --build
# API em http://localhost:8000  |  docs em /docs

cd frontend
npm install && npm run dev
# http://localhost:5173
```

---

## 10. Resumo rápido das ferramentas

| Categoria | Ferramenta | Papel no projeto |
|---|---|---|
| Scanner SAST | **Semgrep** | Padrões perigosos no código próprio |
| Scanner SCA/IaC | **Trivy** | CVEs em dependências + config Docker |
| Scanner Secrets | **Gitleaks** | Segredos vazados no repositório |
| LLM — triagem | **Claude Haiku 4.5** | Score inicial em todos os findings |
| LLM — análise | **Claude Sonnet 4.6** | Análise contextual + geração de diff |
| Backend | **FastAPI + SQLAlchemy + Pydantic** | API REST + ORM + validação |
| Banco | **PostgreSQL 16** (prod) / **SQLite** (dev) | Persistência de assets/scans/findings/clusters |
| Frontend | **React 18 + TS + Vite + Tailwind + React Query** | Dashboard SPA |
| Diff viewer | **react-diff-viewer-continued** | Mostrar remediações no portal |
| Testes | **pytest** | 49 testes automatizados |
| Infra | **Docker + docker-compose** | Backend + Postgres isolados |
| Policies | **YAML + PyYAML** | Regras do gate |
| CI gate | **aspm_gate.py** | Reprova PR com `exit 1` |
