# ULPF — Developer Workflow (Kilo / AGENTS.md)

This file configures agentic development behaviour for the ULPF repository.
It is consumed by the Kilo CLI (`/help`, `.kilo/` command configs).

## Repository Context

- **Working directory:** `D:\Log` (repo root is `D:\Log`).
- **Backend package:** `backend/ulpf` (Python 3.12).
- **Frontend:** `frontend/` (React + Tailwind, introduced in Phase 7).
- **Runtime infra:** `docker-compose.yml` (Kafka, MinIO, OpenSearch, PostgreSQL).
- **Config:** environment variables only. Copy `.env.example` → `.env`.
  Never commit `.env` or secrets.

## Key Conventions

- **Phase discipline:** work proceeds strictly phase-by-phase (see
  `docs/phase-plan.md`). Do not implement Phase N+1 features during a phase.
  Do not create placeholder implementations for future phases.
- **Lossless logs:** never discard or overwrite the original raw payload.
  Normalization is additive; unknown fields are retained under `parsed_fields`.
- **Modularity:** each capability is its own Python sub-package under
  `backend/ulpf/` so new sources can be added without touching the core engine.
- **No hardcoded dashboard data:** the dashboard must render live backend data.
- **Environment first:** all tunables read from env vars with safe defaults.

## Commands

| Task | Command |
|------|---------|
| Backend tests | `cd backend && pytest` |
| Backend tests (with coverage) | `cd backend && pytest --cov=ulpf --cov-report=term-missing` |
| Lint / typecheck | `cd backend && ruff check .` then `mypy ulpf` |
| Start infra | `docker compose up -d` |
| Stop infra | `docker compose down -v` |
| Run backend service (any) | `cd backend && python -m ulpf.api` / `...ingestion` / `...orchestrator` |
| React dev server | `cd frontend && npm install && npm run dev` |

## Testing Strategy

- **Unit tests** (`tests/unit/`): fast, hermetic, no external services.
  Annotated `@pytest.mark.unit`.
- **Integration tests** (`tests/integration/`): require live infra services
  (Kafka, MinIO, OpenSearch, PostgreSQL). Annotated `@pytest.mark.integration`
  and **skipped** unless `ULPF_INTEGRATION=1` is set.
- The full suite must stay green at the end of every phase.

## Git Discipline

- Branch per phase (e.g. `phase/3-parser-engine`).
- One focused commit per phase using the messages in `docs/phase-plan.md`.
- Never commit secrets, `.env`, or local `data/` files.
- Ask before committing; never commit without explicit user instruction.
