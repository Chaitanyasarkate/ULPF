# ULPF React Dashboard

React + Tailwind SOC dashboard for the Universal Log Pre-processing Framework.

## Features

- **Overview**: Real-time KPIs and system status
- **Events**: Searchable event table with pagination
- **Event Detail**: Full event information with lineage visualization
- **Sources**: Source management and onboarding
- **Schema Drift**: Drift detection monitoring
- **Health**: System health monitoring

## Setup

```bash
cd frontend
npm install
npm run dev
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `/api/v1` | Backend API base URL |

## Development

```bash
npm run dev     # Start dev server
npm run build   # Production build
npm run test    # Run tests
npm run lint    # Lint code
```

## Architecture

```
frontend/
├── src/
│   ├── api/           # API client layer
│   │   ├── events.ts   # Events API
│   │   ├── health.ts   # Health API
│   │   ├── lineage.ts  # Lineage API
│   │   ├── schema.ts  # Schema API
│   │   └── sources.ts  # Sources API
│   ├── components/     # Reusable UI components
│   │   ├── Badge.tsx
│   │   ├── Card.tsx
│   │   ├── DataTable.tsx
│   │   ├── KpiCard.tsx
│   │   ├── LoadingStates.tsx
│   │   └── StatusIndicator.tsx
│   ├── pages/          # Page components
│   │   ├── Overview.tsx
│   │   ├── Events.tsx
│   │   ├── EventDetail.tsx
│   │   ├── Sources.tsx
│   │   ├── SchemaDrift.tsx
│   │   └── Health.tsx
│   ├── App.tsx         # Main app with routing
│   └── main.tsx       # Entry point
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

## Real Data Only

This dashboard consumes only real data from the ULPF backend:
- Events from OpenSearch
- Sources from PostgreSQL
- Schema drift from PostgreSQL
- Lineage from PostgreSQL + MinIO
- Health from backend health endpoints

No fake or hardcoded data is displayed.

## Running with Backend

1. Start Docker: `docker compose up -d`
2. Start backend: `cd backend && python -m ulpf`
3. Start frontend: `cd frontend && npm run dev`
4. Open http://localhost:3000
