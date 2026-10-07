# Como rodar o Secure Commit no dia da apresentação

> Deixe este arquivo aberto (segundo monitor / celular / impresso) durante a apresentação.

---

## Modo rápido — só clique 2× nos .bat

Todos os `.bat` estão em `D:\ASPM\`. Rode nesta ordem:

1. **`01-backend-start-fastapi-porta-8000.bat`** — sobe o backend
   → Aguarde `Application startup complete` (~5s)
2. **`02-frontend-start-vite-porta-5173.bat`** — sobe o frontend
   → Aguarde `VITE ready` (~2s)
3. **`03-check-saude-backend-e-frontend.bat`** — verifica se subiu certo
   → Tem que mostrar `"status":"ok"` e `HTTP 200`
4. Deixe **`04-demo-rodar-ci-gate-pygoat.bat`** com o cursor em cima, **NÃO clique ainda** — só na hora da demo do gate

Se algo travar (porta em uso), rode **`05-fix-matar-processos-travados.bat`** e volte pro passo 1.

**Não feche as janelas do 01 e 02 durante a apresentação** — enquanto elas estiverem abertas, o backend e o frontend estão rodando.

---

## Modo manual — comandos diretos (caso um .bat quebre)

**Terminal 1 — Backend:**
```powershell
D:\ASPM\aspm\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir D:\ASPM\aspm\backend
```

**Terminal 2 — Frontend:**
```powershell
cd D:\ASPM\aspm\frontend
npm run dev
```

**Terminal 3 — CI Gate (só na hora):**
```powershell
D:\ASPM\aspm\.venv\Scripts\python.exe D:\ASPM\aspm\backend\bin\aspm_gate.py --api-url http://127.0.0.1:8000 --asset-id c82641e4-8b88-4512-910b-4aec8a39dd7f --policy default
```

---

## Navegador — abas pra abrir antes

- `http://localhost:5173` — dashboard do Secure Commit
- `http://localhost:8000/docs` — API docs (só se algum jurado pedir)

---

## Verificação (30s antes de começar)

Se o `.bat 03` não abrir, teste manualmente:
```powershell
curl http://127.0.0.1:8000/health
```
Tem que voltar `"status":"ok"`. Senão, backend caiu — reinicia o `.bat 01`.

---

## Se der ruim no dia

| Sintoma | Fix |
|---|---|
| `port 8000 already in use` | Rode `05-fix-matar-processos-travados.bat`, depois `01` |
| `port 5173 in use` | Rode `05-fix-matar-processos-travados.bat`, depois `02` |
| Dashboard abre mas mostra erro de rede | Backend caiu — teste `/health` no browser, reinicia `01` |
| Gate dá erro de API key | Backup: mostra scan já pronto no dashboard, pula geração de correção |
| Sem internet no local | Dashboard + gate funcionam **offline** (dados no `aspm.db`). Só não roda **nova análise IA** — use screenshots |

---

## Plano B (notebook morreu / sem tomada / sem internet)

- Tenha **screenshots** no deck: dashboard, finding com rationale, diff colorido
- Tenha um **vídeo curto** (~30s) rodando o gate no celular
- Ensaiar pelo menos 1× sem projeção

---

## Alerta de segurança

A `ANTHROPIC_API_KEY` real está em `D:\ASPM\aspm\.env`.
Se você compartilhar o `secure-commit.zip` com o grupo ou submeter no lugar da avaliação, **rotacione a chave antes** no console da Anthropic (`console.anthropic.com`).

---

## DAST (OWASP ZAP) — opcional

Pré-requisitos: Docker Desktop rodando. O backend chama `docker run --rm zaproxy/zap-stable ...` por scan.

**Puxar a imagem antes da demo** (uma vez só, ~500MB):
```powershell
docker pull zaproxy/zap-stable
```

**Teste de laboratório com Juice Shop** (vulnerável de propósito, autorizado):
```powershell
docker run --rm -d -p 3000:3000 --name juice bkimminich/juice-shop
# No .env do backend:
#   DAST_ALLOWLIST_HOSTS=host.docker.internal
```

**Disparar um scan baseline via API:**
```powershell
curl -X POST http://127.0.0.1:8000/api/dast/scans `
  -H "Content-Type: application/json" `
  -d '{
    "asset_id":"c82641e4-8b88-4512-910b-4aec8a39dd7f",
    "target_url":"http://host.docker.internal:3000",
    "profile":"baseline",
    "options":{"allow_private":true}
  }'
```

Endpoints: `GET /api/dast/profiles`, `POST /api/dast/scans`, `GET /api/dast/scans`, `GET /api/dast/scans/{id}`, `POST /api/dast/scans/{id}/cancel`, `GET /api/dast/scans/{id}/findings`, `GET /api/dast/scans/{id}/report`.

Perfis `active` e `full` exigem `"authorized": true` no payload — o backend recusa com 400 caso contrário. Scans contra URLs públicas de terceiros são bloqueados pelo SSRF guard por padrão. Documentação detalhada em `aspm/dast/README.md`.

---

## CI gate (SAST + DAST)

O `aspm_gate.py` roda os scanners, aguarda, avalia a policy e retorna exit code.

**Exit codes:** `0` passou · `1` reprovado pela policy · `2` erro operacional (API fora, scan falhou, timeout).

**Gate só SAST** (ultimo scan existente):
```powershell
D:\ASPM\aspm\.venv\Scripts\python.exe D:\ASPM\aspm\backend\bin\aspm_gate.py `
  --asset-id <UUID> --policy default
```

**Gate SAST com `--wait`** (dispara + aguarda + avalia):
```powershell
python bin/aspm_gate.py --asset-id <UUID> --policy default --wait
```

**Gate DAST em homologação:**
```powershell
python bin/aspm_gate.py --asset-id <UUID> --policy dast `
  --dast-url https://staging.example.com --dast-profile baseline
```

**Gate completo (SAST + DAST):**
```powershell
python bin/aspm_gate.py --asset-id <UUID> --policy default --wait `
  --dast-url https://staging.example.com --dast-profile baseline
```

**Perfil `active`/`full`** exige `--dast-authorized` explícito; o gate falha com exit 2 se omitir.

Policies disponíveis: `default` (SAST/SCA/secret) e `dast` (regras ZAP). Ver `aspm/dast/README.md` para templates de GitHub Actions/GitLab CI.
