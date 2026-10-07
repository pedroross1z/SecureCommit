# ASPM MVP

Application Security Posture Management com IA (Claude) sobre scanners open-source
(Semgrep, Trivy, Gitleaks).

## Como rodar (dev)

```bash
cp .env.example .env
# edite .env e defina ANTHROPIC_API_KEY

docker compose up --build
```

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

## Frontend (SPA)

O frontend nao esta no docker-compose. Rode local:

```bash
cd frontend
cp .env.example .env.local   # ajuste VITE_API_URL se preciso
npm install
npm run dev
```

Abre em http://localhost:5173 (CORS ja liberado no backend).

## Fases

- [x] **Fase 0** — scaffold, docker-compose, migrations, health check
- [x] **Fase 1** — discovery + collectors + normalizer + API assets/scans/findings
- [x] **Fase 2** — correlacao (clustering por raiz)
- [x] **Fase 3** — priorizacao 2 estagios (Haiku triage + Sonnet deep) + risk_score
- [x] **Fase 4** — remediacao sob demanda (Sonnet gera unified diff + breaking_risk)
- [x] **Fase 5** — frontend (Vite + React + TS + Tailwind; assets/scans/findings/clusters/remediacoes)
- [x] **Fase 6** — policy engine (YAML em `policies/`) + CLI gate (`backend/bin/aspm_gate.py`)

## CI gate

Rode em pipeline para bloquear merge quando a policy falhar:

```bash
python backend/bin/aspm_gate.py \
  --api-url http://localhost:8000 \
  --asset-id <UUID> \
  --policy default \
  --wait
```

- `--wait` dispara um novo scan e aguarda concluir; sem ele, avalia o ultimo scan `done`.
- Exit code: `0` = pass, `1` = fail (rule com `action: fail` violada), `2` = erro operacional.
- Policies ficam em `policies/*.yaml`. Ver `policies/default.yaml` de exemplo.
