# Universal Log Pre-processing Framework (ULPF)

**PS ID:** 26156  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software — Blockchain & Cybersecurity  
**Theme:** Blockchain & Cybersecurity  

ULPF is a vendor-neutral, scalable log-preprocessing framework for
heterogeneous enterprise/network log sources. It is the **preprocessing and
normalization layer** that feeds SIEM, Data Lake, and AI/ML systems — it is
*not* a SIEM itself.

> **Value proposition:**  
> *Heterogeneous logs → Lossless preservation → Universal normalization →
> Traceable analytics-ready events*

## Architecture Overview

```
LOG SOURCES (Firewall/Router/IDS/VPN ... simulators)
        |  Syslog / REST API / File / Stream
        v
INGESTION LAYER  (UDP/TCP syslog, REST API, file tailing)
        |
        v
KAFKA (raw-logs -> parsed-logs -> normalized-events -> failed-events / schema-drift-events)
        |
        v
SOURCE & FORMAT DETECTION   ->   PARSER ENGINE   ->   Parser Registry (YAML)
        |
        v
OCSF-BASED NORMALIZATION (configurable field mappings)
        |
        v
STORAGE LAYER (Phase 5)
        |                       |
        v                       v
  MINIO (raw vault)      OPENSEARCH (normalized, searchable)
        |                       |
        +--- PostgreSQL (metadata + lineage + references)
        |
        v
SHA-256 + HASH CHAIN  ->  Event Lineage / Traceability
        |
        v
FLASK API GATEWAY (REST + SSE/WebSocket)
        |
        v
REACT SOC DASHBOARD
```

## Repository Layout

```
ulpf/
├── docker-compose.yml         # Local dev infrastructure (Phase 0+)
├── backend/                   # Python backend (Flask API, pipeline, storage)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── ulpf/                  # Core package
│   │   ├── __main__.py        # Foundation health/self-test entrypoint
│   │   ├── config.py          # Env-based configuration (Phase 0)
│   │   ├── common/            # Shared: models, hashing, logging
│   │   ├── ingestion/         # Syslog/REST/file listeners + Kafka publisher (Phase 1/2)
│   │   ├── kafka/             # Kafka producer, consumer, topic management (Phase 2)
│   │   ├── parsers/           # Parser engine + registry (Phase 3)
│   │   ├── normalizer/        # OCSF normalization (Phase 4)
│   │   ├── validation/        # Validation + enrichment (Phase 5)
│   │   ├── storage/           # MinIO/OpenSearch/PostgreSQL repos (Phase 5)
│   │   ├── lineage/           # SHA-256 + hash chain + traceability (Phase 6)
│   │   ├── simulators/        # Log source simulators (Phase 1)
│   │   ├── security/          # JWT, RBAC, hashing, audit (Phase 11)
│   │   ├── api/               # Flask REST + SSE gateway (Phase 5/7)
│   │   └── orchestrator/      # Cross-stage orchestration (Phase 2/5)
│   └── tests/{unit,integration}
├── parsers/                   # YAML parser definitions (Phase 3)
├── sample_logs/               # Sample logs per source (Phase 1)
├── frontend/                  # React + Tailwind SOC dashboard (Phase 7)
├── k8s/                       # Kubernetes manifests (Phase 12)
├── docs/                      # Architecture & phase documentation
├── .env.example               # Config template (never commit .env)
├── AGENTS.md                  # Developer workflow & conventions
└── README.md
```

## Quick Start (local, development)

```bash
# 1. Copy the environment template and adjust (dev defaults work out-of-box)
cp .env.example .env

# 2. Start the infrastructure stack
docker compose up -d

# 3. Install & run backend tests
cd backend
python -m venv .venv && . .venv/bin/activate  # (or .venv\Scripts\activate on Windows)
pip install -r requirements.txt
pytest

# 4. Install additional dependencies for pipeline
pip install flask kafka-python minio opensearch-py asyncpg psycopg2-binary requests aiofiles

# 5. Start all services (choose one of the following approaches):

# Option A: Unified API Server (REST API + Ingestion)
python -m ulpf.api

# Option B: Unified Pipeline Runner (Parser + Normalizer + Storage Consumers)
python -m ulpf.orchestrator

# Option C: Run both in separate terminals for full E2E
# Terminal 1:
python -m ulpf.api
# Terminal 2:
python -m ulpf.orchestrator

# 6. Frontend dashboard
cd frontend
npm install && npm run dev
```

## Running the Complete ULPF Pipeline

The ULPF pipeline consists of multiple services that work together:

### Individual Service Commands

| Service | Command | Purpose |
|---------|---------|---------|
| API Server | `python -m ulpf.api` | REST API for sources, schema, lineage, events, health |
| Pipeline Runner | `python -m ulpf.orchestrator` | Parser Engine, Normalizer, Storage Consumers |
| Simulators | `python -m ulpf.simulators.runner` | Firewall/Router/IDS simulators |
| Foundation | `python -m ulpf` | Config validation and self-test |
| Ingestion | `python -m ulpf.ingestion` | Standalone REST ingestion (legacy) |

### Architecture and Data Flow

```
[Firewall Simulator] ---syslog UDP---> [REST API /api/v1/ingest]
[Router Simulator]  ---REST POST-----> [REST API /api/v1/ingest]
[IDS Simulator]    ---REST POST-----> [REST API /api/v1/ingest]
                                 |
                                 v
                           [Kafka: raw-logs]
                                 |
                                 v
                    [Parser Engine] --> [Kafka: parsed-logs]
                                 |
                                 v
                  [Normalizer Engine] --> [Kafka: normalized-events]
                                 |
                    +---------------+---------------+
                    |                               |
                    v                               v
           [Raw Storage Consumer]    [Normalized Storage Consumer]
                    |                               |
                    v                               v
              [MinIO + PostgreSQL]          [OpenSearch + PostgreSQL]
```

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/ingest` | Ingest raw event |
| `GET /api/v1/health` | System health check |
| `GET /api/v1/sources` | List sources |
| `POST /api/v1/sources` | Register source |
| `GET /api/v1/schema/profiles` | List schema profiles |
| `GET /api/v1/schema/drift` | List drift events |
| `GET /api/v1/lineage/event/{id}` | Get lineage chain |
| `GET /api/v1/lineage/verify/{id}` | Verify lineage |
| `GET /api/v1/lineage/raw-event/{id}` | Recover raw event |
| `GET /api/v1/events` | Search events |
| `GET /api/v1/events/{id}` | Get event |
| `GET /api/v1/metrics/summary` | Event metrics |

## Kafka Streaming Pipeline (Phase 2)

ULPF uses **Apache Kafka** as the streaming backbone between ingestion and
downstream processing. Kafka decouples log ingestion from parsing,
normalization, and storage, allowing each stage to scale independently.

### Topics

| Topic | Key | Value | Purpose |
|-------|-----|-------|---------|
| `raw-logs` | `source_id` | `EventEnvelope` | Raw events as they enter ULPF |
| `parsed-logs` | `event_id` | `EventEnvelope` | Parsed events (Phase 3) |
| `normalized-events` | `event_id` | `EventEnvelope` | Normalized events (Phase 4) |
| `failed-events` | `raw_event_id` | `EventEnvelope` | Dead-letter queue for failures |
| `schema-drift-events` | `source_id` | drift alert dict | Schema drift alerts (Phase 10) |

### Configuration

Kafka settings are read from environment variables via `backend/ulpf/config.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker addresses |
| `KAFKA_TOPIC_RAW_LOGS` | `raw-logs` | Raw events topic |
| `KAFKA_GROUP_ID` | `ulpf-processing` | Consumer group id |
| `ULPF_KAFKA_ENABLED` | `false` | Enable Kafka publishing from ingestion |

### Starting Kafka

Kafka is included in `docker-compose.yml` (Phase 0 infrastructure). Start it with:

```bash
docker compose up -d zookeeper kafka
```

Wait for the healthcheck to pass, then run the backend services.

### Testing Kafka

Unit tests mock the Kafka client and do not require a running broker.
Integration tests require `ULPF_INTEGRATION=1` and a reachable Kafka broker:

```bash
export ULPF_INTEGRATION=1
cd backend && pytest tests/integration/test_kafka_pipeline.py -v
```

### Troubleshooting

- **Connection refused:** Ensure Kafka is running and `KAFKA_BOOTSTRAP_SERVERS` matches the container/host address.
- **Topic creation failures:** The admin client creates topics on startup. If it fails, create them manually or ensure Zookeeper is healthy.
- **Message loss:** The producer uses `acks=all` and retries up to 5 times. Check broker logs for under-replicated partitions.

## Parser Engine (Phase 3)

The Parser Engine is the bridge between raw ingestion and downstream
normalization. It consumes `raw-logs` from Kafka, selects the appropriate
parser via the Parser Registry, and emits structured `ParsedEvent` objects to
`parsed-logs`.

### Parser Registry

The registry is the single source of truth for parser discovery. Each parser
registers metadata:

- `parser_id` — unique identifier (e.g. `firewall_syslog_v1`)
- `parser_name` — human-readable name
- `source_type` — logical source class (firewall, router, ids, ...)
- `format` — log format (syslog, json, cef, ...)
- `parser_version` — semantic version
- `enabled` — activation flag

Parser selection considers both `source_type` and `format`. The registry
supports YAML-driven definitions for simple parsers and dedicated Python
classes for complex ones.

### Supported Formats (Phase 3)

| Format | Parser | Source |
|--------|--------|--------|
| Syslog | `FirewallSyslogParser` (`firewall_syslog_v1`) | Firewall |
| JSON | `RouterJsonParser` (`router_json_v1`) | Router |
| CEF | `IDSCEFParser` (`ids_cef_v1`) | IDS/IPS |

### Failure Handling

Parsing failures never discard raw events. Failed envelopes are published to
`failed-events` with an `EventError` recording the stage, code, message, and
traceback. The consumer continues processing subsequent events.

### How to Add a Parser

1. Create a new parser class inheriting from `BaseParser` in `backend/ulpf/parsers/`.
2. Set `parser_id`, `source_type`, `format`, and `parser_version`.
3. Implement the `parse` method returning a `ParsedEvent`.
4. Register the parser in `ParserEngine._register_default_parsers()` or via YAML.
5. Add unit tests in `backend/tests/unit/test_parsers.py`.

## OCSF Normalizer (Phase 4)

The Normalizer converts parsed events into OCSF-aligned common events. It
consumes `parsed-logs` from Kafka and emits `NormalizedEvent` objects to
`normalized-events`.

### Field Mappings

| Source Field | Common Field |
|--------------|--------------|
| `src_ip`, `src` | `source.ip` |
| `dst_ip`, `dst` | `destination.ip` |
| `src_port` | `source.port` |
| `dst_port` | `destination.port` |
| `protocol`, `proto` | `network.protocol` |
| `action`, `act` | `event.action` |
| `severity` | `event.severity` |
| `timestamp`, `rt` | `event.time` |
| `host` | `device.name` |

### Action Normalization

- `allow`: ALLOW, ACCEPT, permitted, pass
- `deny`: DENY, DROP, blocked, block, reject, denied
- `detect`: detected, alerted, alert, identified

### Severity Normalization

- `low`: severity 0-2 (syslog) / 0-3 (CEF)
- `medium`: severity 3-5 (syslog) / 4-6 (CEF)
- `high`: severity 6-7 (syslog) / 7-9 (CEF)
- `critical`: severity 8-10 (CEF)

### Lossless Preservation

All original extracted fields remain in `NormalizedEvent.parsed_fields`.
Normalization never discards data — it only adds common representations.

## Storage Layer (Phase 5)

ULPF stores events across three systems, each with a distinct purpose:

### MinIO (Raw Vault)

- Complete original raw payload stored without modification
- Object key: `raw-events/<date>/<source_type>/<raw_event_id>.json`
- SHA-256 integrity verification on every stored object

### OpenSearch (Normalized Index)

- Date-based indices: `<prefix>-events-YYYY.MM.DD`
- All searchable fields indexed
- Lossless: `ocsf`, `parsed_fields`, and provenance data preserved

### PostgreSQL (Metadata + Lineage)

- `event_metadata`: Core event information
- `raw_object_metadata`: MinIO storage references
- `normalized_object_metadata`: OpenSearch references
- `event_lineage`: Lineage relationships (Phase 6)

## Tamper-Evident Event Provenance (Phase 6)

Phase 6 implements **SHA-256-based integrity verification** and **event
traceability** across the pipeline.

### Lineage Architecture

```
Raw Event (firewall syslog)
    │
    ▼
Parsed Event (structured)
    │
    ▼
Normalized Event (OCSF)
    │
    ▼
Storage (MinIO + OpenSearch + PostgreSQL)
    │
    ▼
Lineage Records (raw→parsed→normalized relationships)
```

### Lineage Relationship Types

| Type | Parent | Child |
|------|--------|-------|
| `parsed_from` | raw_event_id | parsed_event_id |
| `normalized_from` | parsed_event_id | normalized_event_id |

### Verification States

| Status | Meaning |
|--------|---------|
| `VALID` | All checks passed, lineage complete, SHA verified |
| `INVALID` | SHA mismatch detected (tampering evident) |
| `UNAVAILABLE` | Required dependency missing (not verifiable) |

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/lineage/event/{event_id}` | Get complete lineage chain |
| `GET /api/v1/lineage/raw/{raw_event_id}` | Get events by raw ID |
| `GET /api/v1/lineage/verify/{event_id}` | Verify lineage integrity |
| `GET /api/v1/lineage/raw-event/{event_id}` | Recover original raw payload |
| `GET /api/v1/lineage/health` | Check lineage service health |

### Example Usage

```bash
# Get lineage chain for a normalized event
curl http://localhost:5000/api/v1/lineage/event/norm-abc123

# Verify integrity
curl http://localhost:5000/api/v1/lineage/verify/norm-abc123

# Recover original raw event
curl http://localhost:5000/api/v1/lineage/raw-event/norm-abc123
```

### Key Features

- **Backward traceability**: From any event, trace back to the original raw payload
- **Forward traceability**: From raw event, find all derived parsed and normalized events
- **Integrity verification**: SHA-256 hash comparison for tamper detection
- **Idempotent recording**: Duplicate lineage relationships are handled gracefully
- **Lossless recovery**: Original raw payload retrievable from MinIO

## Source Onboarding Manager (Phase 7)

Phase 7 implements **plug-and-play source onboarding** for adding new log sources
without modifying core engine code.

### Source Profile

Each source has a configuration profile stored in PostgreSQL:

| Field | Description |
|-------|-------------|
| `source_id` | Unique identifier (e.g., `firewall.vendor_x`) |
| `source_name` | Human-readable name |
| `source_type` | firewall, router, ids, vpn, etc. |
| `format` | syslog, json, cef, etc. |
| `parser_id` | Parser to use |
| `parser_version` | Parser version |
| `schema_version` | Expected schema version |
| `enabled` | Active/inactive status |

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/sources` | List all sources |
| `POST /api/v1/sources` | Register new source |
| `GET /api/v1/sources/{source_id}` | Get source details |
| `PUT /api/v1/sources/{source_id}` | Update source |
| `DELETE /api/v1/sources/{source_id}` | Unregister source |
| `POST /api/v1/sources/{source_id}/enable` | Enable source |
| `POST /api/v1/sources/{source_id}/disable` | Disable source |

### Example Usage

```bash
# Register a new firewall source
curl -X POST http://localhost:5000/api/v1/sources -H "Content-Type: application/json" \
  -d '{
    "source_id": "firewall.vendor_x",
    "source_name": "Vendor X Firewall",
    "source_type": "firewall",
    "format": "cef",
    "parser_id": "vendor_x_cef",
    "parser_version": "1.0.0"
  }'

# List all sources
curl http://localhost:5000/api/v1/sources

# Disable a source
curl -X POST http://localhost:5000/api/v1/sources/firewall.vendor_x/disable
```

## Schema Drift Detection (Phase 7)

Phase 7 implements **schema drift detection** to identify changes in incoming
event structure while preserving the original event data.

### Core Principle

**DETECT → REPORT → PRESERVE → CONTINUE**

Unexpected fields are never silently discarded.

### Drift Types

| Type | Description | Severity |
|------|-------------|----------|
| `new_field` | Unexpected field in incoming event | INFO |
| `missing_required_field` | Required field not present | ERROR |
| `missing_optional_field` | Optional field not present | INFO |
| `type_change` | Field type differs from expected | WARNING |

### Schema Profile

```yaml
source_id: firewall.vendor_x
schema_version: "1.0.0"

required_fields:
  - src_ip
  - dst_ip
  - action

optional_fields:
  - src_port
  - dst_port
  - protocol

field_types:
  src_ip: string
  dst_ip: string
  src_port: integer
  action: string
```

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/schema/profiles` | List schema profiles |
| `POST /api/v1/schema/profiles` | Register schema |
| `GET /api/v1/schema/profiles/{source_id}` | Get schema |
| `GET /api/v1/schema/drift` | List drift events |
| `GET /api/v1/schema/drift/{event_id}` | Get drift by event |

### Example Usage

```bash
# Register expected schema for a source
curl -X POST http://localhost:5000/api/v1/schema/profiles -H "Content-Type: application/json" \
  -d '{
    "source_id": "firewall.vendor_x",
    "schema_version": "1.0.0",
    "required_fields": ["src_ip", "dst_ip", "action"],
    "optional_fields": ["src_port", "dst_port"],
    "field_types": {"src_ip": "string", "dst_ip": "string", "action": "string"}
  }'

# List drift events
curl http://localhost:5000/api/v1/schema/drift

# Get drift for specific event
curl http://localhost:5000/api/v1/schema/drift/evt-123
```

### Integration with Pipeline

Schema drift detection integrates with the existing processing pipeline:

```
Parsed Event
     ↓
Schema Drift Detector (Phase 7)
     ↓
normal processing (event preserved)
     ↓
OCSF Normalizer (Phase 4)
     ↓
Storage (Phase 5)
     ↓
schema-drift-events (Kafka topic)
```

Events with schema drift continue through the pipeline with drift metadata recorded.

## Phased Delivery

See [`docs/phase-plan.md`](docs/phase-plan.md) for the full phase breakdown.
Development proceeds strictly phase-by-phase; after each phase the test suite
is green and the feature is manually verified before the next phase begins.

## Security Note

This prototype implements **tamper-evident event provenance** using SHA-256 and
hash chaining. This is **not** a blockchain. The term "blockchain" is used only
where an actual blockchain implementation is introduced (none in this project).

## Air-Gapped Deployment (Phase 11)

ULPF is designed to operate in fully air-gapped environments with **zero outbound internet access** at runtime.

### Architecture Guarantees

| Component | Internet Access Required? | Notes |
|-----------|--------------------------|-------|
| Kafka / Zookeeper | No | Internal messaging only |
| MinIO (S3 API) | No | Local object storage |
| OpenSearch | No | Local search index |
| PostgreSQL | No | Local metadata store |
| Flask API | No | Local REST endpoints |
| React Frontend | No | Served locally, no CDN assets |
| Parsers/Normalizers | No | Pure Python, local logic |
| Schema Drift Detection | No | Local PostgreSQL |
| Lineage/Provenance | No | Local SHA-256 + PostgreSQL |
| Simulators | No | Local UDP/HTTP to API |

**No external dependencies at runtime:**
- No telemetry, analytics, or monitoring SaaS
- No CDN-hosted JS/CSS/fonts (Tailwind compiled locally)
- No external API calls (AI parser generator defaults to local `heuristic` provider)
- No package installs at container startup (all deps baked into images)

### Offline Build Process

Run on an **internet-connected build machine**:

```bash
# 1. Build all images
docker compose -f docker-compose.airgap.yml build --parallel

# 2. Save images to a tarball
docker save -o ulpf-airgap-images.tar \
  $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "ulpf|cp-zookeeper|cp-kafka|minio|opensearch|postgres|nginx|node")

# 3. Transfer tarball to air-gapped machine (USB, secure copy, etc.)
```

On the **air-gapped target machine**:

```bash
# 1. Load images
docker load -i ulpf-airgap-images.tar

# 2. Configure environment
cp .env.example .env
# Edit .env with your secrets (JWT_SECRET_KEY, passwords, etc.)

# 3. Start the stack
docker compose -f docker-compose.airgap.yml up -d
```

### Network Isolation

The `docker-compose.airgap.yml` uses an **internal-only Docker network** (`ulpf-internal`) with `internal: true`. This prevents containers from making any outbound connections to the internet. Only the frontend container attaches to an external network (`ulpf-external`) for browser access.

### Verification

Run the network verification script to confirm zero outbound connections:

```bash
python scripts/verify-airgap.py --duration 60
```

This monitors all container network connections for 60 seconds and fails if any non-RFC1918 destination is contacted.

### Image Pinning

All base images use **pinned tags** (not `latest`):

| Service | Image | Tag |
|---------|-------|-----|
| Zookeeper | `confluentinc/cp-zookeeper` | `7.6.1` |
| Kafka | `confluentinc/cp-kafka` | `7.6.1` |
| MinIO | `minio/minio` | `RELEASE.2024-06-07T00-10-36Z` |
| OpenSearch | `opensearchproject/opensearch` | `2.11.1` |
| PostgreSQL | `postgres` | `16-alpine` |
| Python | `python` | `3.12-slim` |
| Node | `node` | `20-alpine` |
| Nginx | `nginx` | `alpine` |

### Runtime Configuration

All configuration via environment variables (`.env` file). No runtime config fetching from external sources.

Required `.env` variables for air-gapped deployment:
```bash
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=<strong-password>
POSTGRES_DB=ulpf
POSTGRES_USER=ulpf
POSTGRES_PASSWORD=<strong-password>
JWT_SECRET_KEY=<32+ char random string>
ULPF_AUTH_ENABLED=true
```

## End-to-End Demo (Phase 12)

ULPF includes a complete E2E demo script that demonstrates the full pipeline
and proves tamper-evident provenance works.

### Quick Demo

```bash
# 1. Start all services (infrastructure + API + pipeline)
docker compose -f docker-compose.airgap.yml up -d
cd backend && python -m ulpf.api &
cd backend && python -m ulpf.orchestrator &

# 2. Run the demo script
python scripts/demo_e2e.py
```

Or use the automated runner:
```bash
./scripts/run_demo.sh
```

### What the Demo Does

1. **Ingests sample logs** — Firewall (syslog), Router (JSON), IDS (CEF)
2. **Shows normalized events** — Events appear in OpenSearch, queryable via API
3. **Tamper with raw log** — Directly modifies a raw event in MinIO
4. **Verify integrity fails** — Calls `GET /api/v1/lineage/verify/{id}` and shows SHA-256 mismatch
5. **Recover raw event** — Shows tampered content with failed verification

### Demo Output Example

```
=== BEFORE TAMPERING ===
Verification result: {"verified": true, "sha256_match": true, ...}
✓ Integrity check PASSED before tampering

=== TAMPERING ===
✓ Tampered with raw event in MinIO: raw-events/2026.09.26/firewall/raw-abc123.json

=== AFTER TAMPERING ===
Verification result: {"verified": false, "sha256_match": false, "expected_sha256": "...", "actual_sha256": "..."}
✓ Integrity check FAILED after tampering (EXPECTED!)

=== RECOVERY ATTEMPT ===
Integrity check FAILED (expected): {"error": "Integrity verification failed", "sha256": "...", "expected_sha256": "..."}
```

### Demo Requirements

- All infrastructure services running (Kafka, MinIO, OpenSearch, PostgreSQL)
- Backend API running on port 5000
- Pipeline runner consuming from Kafka
- Valid JWT token (demo users: admin/analyst/viewer)

### Dashboard Verification

After running the demo, open the React dashboard at `http://localhost:5173`:
- Login with `admin` / `ulpf-admin-demo`
- Navigate to **Events** page to see ingested events
- Click an event to see **Event Detail** with lineage visualization
- Navigate to **Health** page to verify all services healthy

## License & Acknowledgements

Built for the Smart India Hackathon 2026 problem statement 26156.
