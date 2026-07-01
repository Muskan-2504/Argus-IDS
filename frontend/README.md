# Argus Frontend

The analyst dashboard — **React 18 + TypeScript + Vite + Tailwind**, with
Chart.js and a D3 world attack map for visualization.

## Features

- **Login** via the API's OAuth2 flow; JWT persisted in `localStorage`.
- **Threat overview** — stat cards (total / open / high+critical / source IPs).
- **Charts** — alert mix by severity (doughnut) and alert volume over time (bar).
- **Alert table** — severity & status badges, clickable MITRE technique links,
  filters (severity / status / source IP), and **inline triage** (acknowledge /
  resolve / false-positive) for analysts and admins.
- **Real-time** — a WebSocket stream pushes new alerts into a live feed, the
  attack map, and the table; a poll backstops a dropped socket.
- **Attack map** — a D3 world map plots alert origins from IP enrichment.

## Develop

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173  (proxies /api to http://localhost:8000)
```

Run the backend (`uvicorn app.main:app --reload`) alongside it, then sign in
with the admin you created via `python -m app.cli create-admin`.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the Vite dev server with API proxy |
| `npm run build` | Type-check (`tsc -b`) and produce a production build |
| `npm run lint` | ESLint (flat config) |
| `npm run typecheck` | Type-check without emitting |

## Structure

```
src/
├── api/         typed client + domain types (mirrors backend schemas)
├── auth/        AuthProvider, context, useAuth hook
├── components/  Header, LoginForm, AlertTable, AlertFilters, StatCards, charts, badges
├── lib/         formatting + label helpers
└── pages/       Dashboard
```
