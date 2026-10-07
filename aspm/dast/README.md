# ASPM DAST — OWASP ZAP

Modulo DAST integrado ao Secure Commit. Executa OWASP ZAP via Docker.

## Perfis

| Perfil     | O que faz                                       | Autorizacao |
|------------|-------------------------------------------------|-------------|
| `passive`  | Spider + passive scan (sem payloads)            | nao         |
| `baseline` | Spider + ajax + passive                         | nao         |
| `active`   | + active scan (payloads ofensivos)              | **sim**     |
| `full`     | Descoberta profunda + passive + active          | **sim**     |

`active` e `full` requerem `authorized=true` no payload da API; o backend
recusa com HTTP 400 caso contrario.

## Como o backend chama o ZAP

O backend FastAPI invoca `docker run --rm zaproxy/zap-stable zap-baseline.py ...`
por scan. Nao exige subir o compose; basta ter Docker rodando no host.

Os perfis YAML neste diretorio (`passive.yaml`, `baseline.yaml`, `active.yaml`)
sao templates do Automation Framework do ZAP e ficam versionados para uso
manual ou para evolucao futura (planos sob medida por asset).

## Debug: subir o ZAP como daemon

```bash
docker compose -f dast/docker-compose.dast.yml --profile debug up zap
# API ZAP em http://127.0.0.1:8090 (chave: $ZAP_API_KEY)
```

Esse modo nao e usado pelo backend em producao e so bind em loopback.

## Seguranca

- Container nunca sobe com `privileged`.
- Limites de CPU/memoria aplicados via `--cpus` e `--memory`.
- API administrativa do ZAP so em loopback no modo debug.
- Backend valida URL contra SSRF (loopback/privadas/metadata) antes de
  disparar; so permite privadas se o host estiver em `DAST_ALLOWLIST_HOSTS`.

## Variaveis de ambiente relevantes

| Env                      | Default                | Para que serve                  |
|--------------------------|------------------------|---------------------------------|
| `DAST_ZAP_IMAGE`         | `zaproxy/zap-stable`   | Imagem do ZAP                   |
| `DAST_CPU_LIMIT`         | `2`                    | `--cpus` do container ZAP       |
| `DAST_MEM_LIMIT`         | `2g`                   | `--memory` do container ZAP     |
| `DAST_ALLOWLIST_HOSTS`   | (vazio)                | Hosts privados autorizados      |
| `DOCKER_BIN`             | `docker`               | Caminho do bin docker           |
| `ZAP_API_KEY`            | `change-me`            | Chave API (modo daemon/debug)   |

## Teste de ponta a ponta (laboratorio)

Use OWASP Juice Shop em outra porta local:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
# Autorize em DAST_ALLOWLIST_HOSTS=host.docker.internal
```
Alvo: `http://host.docker.internal:3000` com perfil `baseline`.
Nunca aponte para sistemas de terceiros.

## Integracao com CI/CD

O `aspm_gate.py` (em `backend/bin/`) dispara o DAST, aguarda e avalia a
policy. Exit codes: 0 passou · 1 reprovado · 2 erro operacional.

### GitHub Actions

```yaml
# .github/workflows/aspm-dast.yml
name: ASPM DAST gate
on:
  push:
    branches: [main]
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy staging
        run: ./deploy-staging.sh
      - name: ASPM DAST gate
        env:
          ASPM_URL: ${{ secrets.ASPM_URL }}
          ASSET_ID: ${{ vars.ASPM_ASSET_ID }}
          STAGING_URL: ${{ vars.STAGING_URL }}
        run: |
          pip install httpx
          python aspm/backend/bin/aspm_gate.py \
            --api-url "$ASPM_URL" \
            --asset-id "$ASSET_ID" \
            --policy dast \
            --dast-url "$STAGING_URL" \
            --dast-profile baseline \
            --requested-by "gh-actions-${{ github.run_id }}"
```

### GitLab CI

```yaml
# .gitlab-ci.yml (trecho)
dast-gate:
  stage: security
  image: python:3.11-slim
  script:
    - pip install httpx
    - python aspm/backend/bin/aspm_gate.py
        --api-url "$ASPM_URL"
        --asset-id "$ASSET_ID"
        --policy dast
        --dast-url "$CI_ENVIRONMENT_URL"
        --dast-profile baseline
        --requested-by "gitlab-$CI_JOB_ID"
  only:
    - main
```

### Observacoes

- Rode o DAST **apos** deploy em homologacao. Nunca aponte para producao
  sem autorizacao expressa e perfil adequado (`active`/`full` + `--dast-authorized`).
- Para alvos privados (homologacao interna), configure `DAST_ALLOWLIST_HOSTS`
  no backend e passe `--dast-allow-private` no gate.
- Para distinguir "scan nao rodou" de "policy reprovou": o exit code 2
  (erro operacional) deve falhar o pipeline **sem** marcar como vulnerabilidade;
  exit 1 e vulnerabilidade detectada.
- A policy `dast` (em `aspm/policies/dast.yaml`) cobre: severidade high,
  risk-score IA >= 80, CWEs top-offenders (SQLi/XSS/SSRF/RCE/CMDi).
  Severidade media vira warning e nao bloqueia.
