# ULPF — Phase Plan

Strict, sequential phase delivery. Each phase ends with: green tests, manual
verification, documentation update, and a focused git commit. Do **not** start
Phase N+1 until the user issues `NEXT PHASE`.

## Phase 0 — Project Foundation & Repository Structure (THIS)

Establish the repository scaffold, configuration layer, core data model,
hashing/lineage primitives, test infrastructure, and documentation. The
backend package must build and the foundation self-test + unit tests must pass.

- Directory scaffolding (`backend/ulpf/{common,ingestion,parsers,normalizer,...}`)
- Env-based configuration (`config.py`, `.env.example`)
- Core data model (`common/models.py`: `EventEnvelope`, `RawEvent`, `ParsedEvent`, `NormalizedEvent`)
- Hashing & hash-chain foundation (`common/hashing.py`, `common/logging.py`)
- `python -m ulpf` self-test entrypoint
- Test infra (`pytest`, `conftest`, unit + integration smoke tests)
- Infrastructure `docker-compose.yml` (Kafka, MinIO, OpenSearch, PostgreSQL)
- `backend/Dockerfile`
- `README.md`, `AGENTS.md`, `docs/architecture.md`
- Initial `backend/requirements.txt`

## Phase 1 — Log Ingestion + Realistic Log Simulators

- Syslog listener (UDP + TCP), REST API ingest endpoint, file-tailing ingest.
- Continuous realistic simulators for: Firewall (Syslog), Router (JSON), IDS (CEF).
- Events enter the `raw-logs` path.

## Phase 2 — Kafka Streaming Pipeline

- Kafka producer service (`UlpfProducer`) publishing `EventEnvelope` to `raw-logs`.
- Kafka consumer service (`UlpfConsumer`) reading from `raw-logs` with validation.
- Topic initialization via `KafkaAdminClient`.
- Ingestion integration: optional Kafka mode via `ULPF_KAFKA_ENABLED`.
- Retry, delivery confirmation, graceful shutdown, structured logging.
- Configurable topics, partition count, and consumer group.
- Producer/consumer unit tests + integration tests (requires running Kafka).

## Phase 3 — Parser Engine + Parser Registry

- Modular parser engine consuming `raw-logs` from Kafka.
- Parser registry with source-type + format-aware lookup.
- Built-in parsers: Syslog (Firewall), JSON (Router), CEF (IDS/IPS).
- YAML-configurable parser definitions for extensibility.
- Parser versioning (`parser_id`, `parser_version`) on every parsed event.
- Failed events published to `failed-events` with `EventError` metadata.
- Format detection layer (syslog / json / cef / unknown).
- Source-aware parser selection without hardcoded if/else chains.
- Comprehensive unit + integration tests.

## Phase 4 — OCSF-Based Universal Event Normalization

- Consume `parsed-logs` from Kafka.
- Map source-specific fields to OCSF-aligned common representation.
- Action normalization (allow/deny/detect/unknown).
- Severity normalization (low/medium/high/critical).
- Timestamp normalization to ISO-8601 UTC.
- Network field validation (IP, port, protocol).
- Lossless preservation: all original fields retained in `parsed_fields`.
- Provenance: `raw_event_id`, `event_id`, `sha256`, `parser_id`, `parser_version`.
- Schema versioning (`schema_version` default `1.0.0`).
- Publish normalized events to `normalized-events`; failures to `failed-events`.

## Phase 5 — Storage (MinIO + OpenSearch + PostgreSQL)

- Losslessly store raw payloads in MinIO with SHA-256.
- Index normalized events in OpenSearch.
- Persist metadata (users, parser registry, sources, schema versions) in PostgreSQL.

## Phase 6 — Event Lineage + SHA-256 + Hash Chain (COMPLETE)

**Status**: Implemented ✅

- Tamper-Evident Event Provenance: raw→parsed→normalized lineage.
- SHA-256-based integrity verification service.
- Lineage API with REST endpoints for chain retrieval and verification.
- PostgreSQL `event_lineage` table with ancestry/descendant queries.
- Recovery of original raw payloads from MinIO.

### Implementation

| Component | File | Description |
|-----------|------|-------------|
| Models | `ulpf/lineage/models.py` | LineageRecord, LineageChain, LineageVerification, RawEventRecovery |
| Repository | `ulpf/lineage/repository.py` | PostgreSQL lineage storage with event_lineage table |
| Service | `ulpf/lineage/service.py` | High-level lineage operations, verification, recovery |
| API | `ulpf/lineage/api.py` | Flask blueprint with REST endpoints |
| Tests | `tests/unit/test_lineage_*.py` | Unit tests for models, repository, service |
| Integration | `tests/integration/test_lineage.py` | Integration tests (requires Docker) |

### API Endpoints

```
GET /api/v1/lineage/event/{event_id}     - Get lineage chain
GET /api/v1/lineage/raw/{raw_event_id}   - Get events by raw ID
GET /api/v1/lineage/verify/{event_id}    - Verify lineage integrity
GET /api/v1/lineage/raw-event/{event_id}  - Recover original raw payload
GET /api/v1/lineage/health                - Health check
```

## Phase 7 — Source Onboarding + Schema Drift Detection (COMPLETE)

**Status**: Implemented ✅

Phase 7 implements plug-and-play source onboarding and schema drift detection.

### Source Onboarding Implementation

| Component | File | Description |
|-----------|------|-------------|
| Models | `ulpf/onboarding/models.py` | SourceProfile, SourceType, LogFormat, SourceStatus |
| Repository | `ulpf/onboarding/repository.py` | PostgreSQL source_profiles table |
| Manager | `ulpf/onboarding/manager.py` | SourceOnboardingManager with validation |
| API | `ulpf/api/sources.py` | Flask blueprint with CRUD endpoints |
| Tests | `tests/unit/test_onboarding_*.py` | Unit tests for models and manager |

### Source Onboarding API

```
GET /api/v1/sources                - List sources
POST /api/v1/sources             - Register source
GET /api/v1/sources/{source_id}  - Get source
PUT /api/v1/sources/{source_id}  - Update source
DELETE /api/v1/sources/{source_id} - Unregister source
POST /api/v1/sources/{source_id}/enable - Enable source
POST /api/v1/sources/{source_id}/disable - Disable source
```

### Schema Drift Detection Implementation

| Component | File | Description |
|-----------|------|-------------|
| Models | `ulpf/schema/models.py` | SchemaProfile, DriftDetectionResult, DriftEvent |
| Repository | `ulpf/schema/repository.py` | PostgreSQL schema_profiles + schema_drift_events tables |
| Detector | `ulpf/schema/detector.py` | SchemaDriftDetector with type inference |
| API | `ulpf/api/schema.py` | Flask blueprint with schema/drift endpoints |
| Tests | `tests/unit/test_schema_*.py` | Unit tests for models and detector |

### Schema Drift API

```
GET /api/v1/schema/profiles           - List schema profiles
POST /api/v1/schema/profiles          - Register schema
GET /api/v1/schema/profiles/{source_id} - Get schema
GET /api/v1/schema/drift              - List drift events
GET /api/v1/schema/drift/{event_id}  - Get drift by event
```

### Drift Detection Principle

**DETECT → REPORT → PRESERVE → CONTINUE**

Events with schema drift continue processing. Unknown fields are preserved
in `parsed_fields` and never discarded.

### Drift Types

| Type | Description | Severity |
|------|-------------|----------|
| `new_field` | Unexpected field detected | INFO |
| `missing_required_field` | Required field missing | ERROR |
| `missing_optional_field` | Optional field missing | INFO |
| `type_change` | Field type mismatch | WARNING |

## Phase 8 — Live React SOC Dashboard + Integration (COMPLETE)

**Status**: Implemented ✅

Phase 8 implements a professional React + Tailwind SOC dashboard and
completes the Phase 1-8 integration.

### Dashboard Features

| Page | Description |
|------|-------------|
| Overview | Real-time KPIs, system status, events by source/action/severity |
| Events | Searchable event table with pagination and filtering |
| Event Detail | Full event info with lineage visualization and raw payload recovery |
| Sources | Source management and onboarding with validation |
| Schema Drift | Drift detection monitoring with severity classification |
| Health | System health monitoring with service status |

### Frontend Architecture

```
frontend/
├── src/
│   ├── api/           # API client layer
│   ├── components/     # Reusable UI components
│   ├── pages/         # Page components
│   ├── App.tsx        # Main app with routing
│   └── main.tsx        # Entry point
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

### API Integration

The dashboard reuses existing backend APIs:
- `/api/v1/events` - Event search and retrieval
- `/api/v1/lineage/*` - Lineage and verification
- `/api/v1/sources/*` - Source management
- `/api/v1/schema/*` - Schema profiles and drift
- `/api/v1/health` - System health

### Key Features

- Real data only (no fake/hardcoded values)
- Auto-refresh every 30 seconds
- Loading/error/empty states
- Professional SOC styling with Tailwind
- Responsive design

### Unified Pipeline Runner (Integration Complete)

Phase 8 includes the integration of all Phase 1-8 components into a unified pipeline:

#### Entry Points

| Command | Purpose |
|---------|---------|
| `python -m ulpf.api` | Unified REST API server (sources, schema, lineage, events, health) |
| `python -m ulpf.orchestrator` | Pipeline runner (Parser, Normalizer, Storage Consumers) |
| `python -m ulpf.simulators.runner` | Log simulators (Firewall, Router, IDS) |
| `python -m ulpf` | Foundation self-test |

#### E2E Data Flow

```
Simulators --> Ingestion --> Kafka (raw-logs)
                                 |
                                 v
                         [Parser Engine] --> Kafka (parsed-logs)
                                 |
                                 v
                        [Normalizer Engine] --> Kafka (normalized-events)
                                 |
                    +------------+---------------+
                    |                           |
                    v                           v
            [Raw Storage Consumer]    [Normalized Storage Consumer]
                    |                           |
                    v                           v
              [MinIO + PostgreSQL]      [OpenSearch + PostgreSQL]
                    |                           |
                    +------------+---------------+
                                 |
                                 v
                      [REST API] --> [React Dashboard]
```

## Phase 9 — AI-Assisted Parser Generator

- Optional, configurable AI provider; suggests parser + mappings; validation;
  human approval before registry. Core runs without AI (air-gapped).

## Phase 10 — Authentication + RBAC + Security

- JWT auth; roles (admin/analyst/viewer) enforced server-side.
- Password hashing; audit logging; RBAC decorators on all APIs.

## Phase 11 — Docker + Air-Gapped Deployment

- Dockerfiles, docker-compose (full). Kubernetes manifests.
- Offline bundle + air-gap install/run docs.

## Phase 12 — End-to-End + Performance + Demo

- Full demo flow verification. Benchmarks (events/sec, latency, success rates).
  Demo script + documentation.

## Suggested Commit Messages

| Phase | Message |
|-------|---------|
| 0 | `phase-0-foundation` |
| 1 | `phase-1-ingestion` |
| 2 | `phase-2-kafka` |
| 3 | `phase-3-parser-engine` |
| 4 | `phase-4-ocsf-normalization` |
| 5 | `phase-5-storage` |
| 6 | `phase-6-event-lineage` |
| 7 | `phase-7-source-onboarding-schema-drift` |
| 8 | `phase-8-live-dashboard` |
| 9 | `phase-9-ai-parser` |
| 10 | `phase-10-auth-rbac` |
| 11 | `phase-11-deployment` |
| 12 | `phase-12-testing` |
