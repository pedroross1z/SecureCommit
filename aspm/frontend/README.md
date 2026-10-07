# ASPM Frontend

SPA em Vite + React + TypeScript + Tailwind. Consome o backend FastAPI em `http://localhost:8000`.

## Rodar dev

```
cp .env.example .env.local   # ajuste VITE_API_URL se preciso
npm install
npm run dev
```

Abre em http://localhost:5173. O backend precisa estar rodando (docker compose up ou uvicorn local).

## Scripts

- `npm run dev` — Vite dev server + HMR
- `npm run build` — typecheck + build para `dist/`
- `npm run typecheck` — apenas tsc --noEmit
- `npm run preview` — serve o build local
