# Secure Commit — ASPM com IA

Plataforma educacional de **Application Security Posture Management** que
centraliza resultados de scanners de segurança (SAST, SCA, secret scanning,
DAST), elimina alertas duplicados, usa IA da Anthropic para priorizar
vulnerabilidades e sugere correções.

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL (prod) / SQLite (dev)
- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, TanStack React Query
- **Scanners**: Semgrep (SAST), Trivy (SCA/IaC), Gitleaks (secrets), OWASP ZAP (DAST)
- **IA**: Claude Haiku (triagem em lote) + Claude Sonnet (análise profunda e remediação)
- **Infra**: Docker, Docker Compose

**Status**: 161 testes passando no backend. Fases implementadas:
MVP backend DAST, frontend DAST, CI gate, correlator DAST↔SAST,
prompts dedicados DAST e **monitor DAST contínuo** (ZAP daemon + polling).

---

## Como rodar — passo a passo

### Pré-requisitos

| Ferramenta        | Versão mínima | Observação                                        |
|-------------------|---------------|---------------------------------------------------|
| Python            | 3.11          | Para o backend                                    |
| Node.js           | 18            | Para o frontend                                   |
| Docker Desktop    | 4.x           | Opcional, só para DAST (ZAP + Juice Shop)         |
| Chave Anthropic   | —             | Grátis em console.anthropic.com (opcional)        |

A IA é **opcional** — sem `ANTHROPIC_API_KEY` o sistema roda sem IA (findings
sem triagem, sem risk score, sem remediação sugerida). Scanners e policies
continuam funcionando.

### 1. Clonar

```bash
git clone https://github.com/<seu-user>/secure-commit.git
cd secure-commit
```

### 2. Backend

```bash
# Cria venv e instala dependências
python -m venv aspm/.venv
# Windows:
aspm/.venv/Scripts/activate
# Linux/Mac:
source aspm/.venv/bin/activate

pip install -r aspm/backend/requirements.txt

# Configura env
cp aspm/.env.example aspm/.env
# edita aspm/.env e cola ANTHROPIC_API_KEY=sk-ant-... (opcional)
```

### 3. Sobe o backend

```bash
cd aspm/backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Testa: http://127.0.0.1:8000/health deve retornar `{"status":"ok"}`.

Documentação da API (OpenAPI/Swagger): http://127.0.0.1:8000/docs

### 4. Sobe o frontend (outro terminal)

```bash
cd aspm/frontend
npm install
npm run dev
```

Dashboard: http://localhost:5173

### Alternativa Windows — scripts prontos

Da raiz, dê duplo-clique nessa ordem:

1. `01-backend-start-fastapi-porta-8000.bat`
2. `02-frontend-start-vite-porta-5173.bat`
3. `03-check-saude-backend-e-frontend.bat` (valida)

Se as portas estiverem travadas: `05-fix-matar-processos-travados.bat`.

---

## Fluxo básico (SAST + IA)

1. Dashboard → **+ Adicionar asset** → cola URL do repo (ex: `https://github.com/pyupio/pygoat`)
2. No asset, clica **Rodar novo scan**
3. Backend roda Semgrep + Trivy + Gitleaks em paralelo, normaliza findings,
   dispara **triagem Haiku** (todos os findings) e **deep analysis Sonnet**
   nos top 5 de risco
4. Dashboard mostra findings com severity, risk score, rationale da IA
5. Em cada finding: botão **Aprofundar** (re-analisa) e **Gerar patch**
   (Sonnet produz diff unified aplicável com `git apply`)

---

## Fluxo DAST (OWASP ZAP) — opcional

Precisa de Docker Desktop rodando.

### Modo 1: Scan one-shot

Rápido, bom para CI/CD gate:

1. Sobe Juice Shop local (app deliberadamente vulnerável):
   ```bash
   docker pull bkimminich/juice-shop
   docker run --rm -d -p 3000:3000 --name juice bkimminich/juice-shop
   ```
2. No `.env` do backend, autorize o host local:
   ```
   DAST_ALLOWLIST_HOSTS=host.docker.internal,localhost
   ```
   Reinicie o backend.
3. Dashboard → asset → tab **DAST** → **+ Novo scan DAST**:
   - URL alvo: `http://host.docker.internal:3000`
   - Perfil: `baseline` (passive + spider)
   - Marque "Permitir alvo privado"
4. Backend puxa `zaproxy/zap-stable` (~500MB no primeiro scan) e dispara.
5. Em ~1min você vê findings DAST com URL/método/parâmetro/evidência
   na tabela de Findings.

Perfis `active` e `full` exigem `--authorized` explícito — o backend
recusa com HTTP 400 caso contrário.

### Modo 2: Monitor contínuo (ZAP daemon ao vivo)

ZAP persistente que fica achando novas vulnerabilidades conforme a app muda:

1. Mesmo setup do Modo 1 (Juice Shop + `DAST_ALLOWLIST_HOSTS`).
2. Dashboard → asset → tab **DAST** → bloco verde **Monitor contínuo** →
   **+ Iniciar monitor**
   - URL: `http://host.docker.internal:3000`
   - Intervalo de poll: `60s` (15-3600s)
3. Backend sobe container `aspm-zap-monitor-<id>` em porta dinâmica
   (18080-18200), dispara spider inicial, scheduler asyncio polla a
   ZAP API a cada 60s.
4. Status muda `starting → running`. A cada poll, novos alerts aparecem
   como findings. Clica **Re-spider** depois de um deploy pra descobrir
   rotas novas. **Parar** mata o container.

Findings do monitor aparecem na **tabela principal de Findings** do asset,
com mesmo UX da análise estática: severity, risk score (triagem Haiku),
botão aprofundar.

---

## CI gate (SAST + DAST)

O `aspm_gate.py` roda scanners, avalia policy e retorna exit code
determinístico.

```bash
# Só SAST — avalia último scan
python aspm/backend/bin/aspm_gate.py --asset-id <UUID> --policy default

# SAST + aguardar
python aspm/backend/bin/aspm_gate.py --asset-id <UUID> --policy default --wait

# DAST em staging
python aspm/backend/bin/aspm_gate.py --asset-id <UUID> --policy dast \
  --dast-url https://staging.example.com --dast-profile baseline

# Perfil ofensivo (exige flag)
python aspm/backend/bin/aspm_gate.py --asset-id <UUID> --policy dast \
  --dast-url https://staging.example.com --dast-profile active \
  --dast-authorized
```

**Exit codes:**
- `0` — passou
- `1` — reprovado pela policy
- `2` — erro operacional (API fora, scan falhou, timeout)

Templates para GitHub Actions e GitLab CI em `aspm/dast/README.md`.

---

## Policies

Policies YAML em `aspm/policies/`:

- **`default.yaml`** — bloqueia secrets, severity critical, CVEs high+, risk score IA ≥ 80
- **`dast.yaml`** — bloqueia findings DAST severity high, risk ≥ 80, CWEs top offenders (SQLi, XSS, SSRF, RCE, cmd injection)

Edite ou crie novas policies. O policy engine aceita condições:
`category_in`, `severity_in`, `min_risk_score`, `cwe_any`, `cve_present`,
`package_name_in`, `rule_id_in`, `tool_in`, `exclude_status`.

---

## Arquitetura DAST

```
┌─────────────────┐
│   Dashboard     │  React + Vite
│  (localhost:    │  Modal "iniciar monitor"
│      5173)      │  Card status ao vivo
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  FastAPI        │  Scheduler asyncio (lifespan)
│  (localhost:    │  Endpoints /api/dast/*
│      8000)      │  SSRF guard, autorização server-side
└────────┬────────┘
         │ docker run
         ▼
┌─────────────────┐       ┌─────────────────┐
│  ZAP daemon     │ ────▶ │  Alvo web       │
│  :18099 (API)   │  HTTP │  (Juice Shop)   │
│  container      │       │                 │
│  isolado        │       └─────────────────┘
└────────┬────────┘
         │ ZAP REST API (/JSON/core/view/alerts)
         ▼ polling 60s
┌─────────────────┐
│  Normalizer     │  → RawFinding (category='dast')
│  + Upsert       │  dedup por fingerprint
│  + Correlator   │  DAST↔SAST via CWE comum
│  + Triagem IA   │  Haiku pontua risk_score
└─────────────────┘
```

### Segurança do próprio DAST

- **SSRF guard** (`aspm/backend/app/core/dast/ssrf.py`): resolve DNS,
  bloqueia loopback, link-local, redes privadas, metadata de cloud
  (169.254.169.254, metadata.google.internal), portas sensíveis.
  Alvos privados exigem `DAST_ALLOWLIST_HOSTS` explícito.
- **Autorização server-side**: perfis ativos (`active`/`full`) só rodam
  com `authorized=true` no payload. O backend recusa; não há bypass pela UI.
- **Container isolado**: `--rm`, limites de CPU/memória, sem `--privileged`,
  volume só do workdir do scan.
- **API key única por monitor**: cada ZAP daemon tem chave gerada com
  `secrets.token_urlsafe`.
- **Dedup**: fingerprint SHA256 de `host + rota + parâmetro + CWE` evita
  duplicação em polls recorrentes.

---

## Testes

```bash
# Backend (pytest)
cd aspm/backend
python -m pytest tests -q
# → 161 passed

# Frontend (build check)
cd aspm/frontend
npm run build
# → 200 modules, 0 TypeScript errors
```

Cobertura:
- Unit tests: SSRF, normalizers, profiles, prompts, correlator, policy engine, prioritizer
- Integration tests: service DAST completo, API via TestClient, executor com subprocess mockado, monitor com ZAP mockado
- CI gate: 14 testes com httpx.MockTransport cobrindo exit codes, autorização DAST, combos SAST+DAST

---

## Variáveis de ambiente

```bash
# aspm/.env
ANTHROPIC_API_KEY=sk-ant-...          # opcional (IA degrada graciosamente)
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///./aspm.db      # default dev; prod usa Postgres via docker-compose

# DAST
DAST_ZAP_IMAGE=zaproxy/zap-stable
DAST_CPU_LIMIT=2
DAST_MEM_LIMIT=2g
DAST_ALLOWLIST_HOSTS=                 # separado por vírgula (ex: host.docker.internal,localhost)
```

---

## Documentação adicional

| Arquivo                    | Conteúdo                                           |
|----------------------------|----------------------------------------------------|
| `COMO_RODAR.md`            | Guia rápido para apresentação                      |
| `SOBRE_O_PROJETO.md`       | Visão geral do produto                             |
| `BRIEFING.md`              | Briefing original do trabalho                      |
| `aspm/dast/README.md`      | Deep dive do módulo DAST + templates CI            |
| `aspm/backend/README.md`   | Backend API                                        |

---

## Licença

Projeto acadêmico/educacional. Scanners de terceiros têm licenças próprias:
Semgrep (LGPL-2.1), Trivy (Apache-2.0), Gitleaks (MIT), OWASP ZAP (Apache-2.0).
