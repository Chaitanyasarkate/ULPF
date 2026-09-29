# ULPF Architecture

> Authoritative design reference. Updates to this document must stay in lock-step
> with implementation decisions.

## 1. Principles

1. **Lossless preservation.** The exact original payload is retained in the
   raw vault; normalization never drops fields (extracted fields are mirrored
   under `parsed_fields`).
2. **Traceability.** Every normalized event carries `raw_event_id`, `event_id`,
   `parser_id`, `parser_version`, `schema_version`, and cryptographic hashes
   that let an analyst retrieve the exact original event and prove it was not
   tampered with.
3. **Vendor neutrality.** Source-specific behaviour lives entirely in YAML
   parser definitions + field-mapping configurations, not in the core engine.
4. **Modularity & loose coupling.** Ingestion, parsing, normalization,
   validation, storage, and lineage are separate services that communicate via
   Kafka — each can scale independently.
5. **Air-gapped operability.** No mandatory external/cloud dependency. The AI
   parser generator is opt-in and the core pipeline runs fully offline.
6. **Security by enforcement.** Authorization is enforced server-side; the
   frontend never trusts client-side route hiding.

## 2. Core Data Model (single source of truth)

See `backend/ulpf/common/models.py`. Two envelopes carry data:

| Field | Envelope stage |
|-------|----------------|
| `raw_event_id` | `RawEvent` (stable identity of the original payload) |
| `event_id` | `ParsedEvent` (fresh id generated at first parse) |
| `source_id` / `source_type` | `RawEvent` |
| `format` | `RawEvent` (detected: syslog / json / cef / ...) |
| `parser_id` / `parser_version` | `ParsedEvent` (selected from registry) |
| `schema_version` | envelope constant `1.0.0`; bumped on normalization changes |
| `event_timestamp` | extracted by parser (the "when" of the event) |
| `ingestion_timestamp` | envelope (the "when" it entered ULPF) |
| `original_payload` | `RawEvent.payload` (immutable) |
| `normalized_event` | OCSF dict |
| `sha256` | SHA-256 of raw payload content fingerprint |
| `previous_hash` / `current_hash` | hash-chain linkage |
| `processing_status` | enum across the pipeline lifecycle |
| `error` | optional `EventError` (stage + code + message + traceback) |

## 3. Services

| Service | Language | Responsibility | Phase |
|---------|----------|----------------|-------|
| `simulators` | Python | Generate realistic live logs (Firewall/Syslog, Router/JSON, IDS/CEF, VPN/JSON) | 1 |
| `ingestion` | Python (Flask) | Syslog UDP/TCP + REST API + file ingestion → Kafka `raw-logs` topic | 1, 2 |
| `parser-engine` | Python | Consume `raw-logs`; format/source detection; parser selection; emit `parsed-logs` / `failed-events` | 2, 3 |
| `normalizer` | Python | Consume `parsed-logs`; OCSF normalization; emit `normalized-events` / `schema-drift-events` | 4 |
| `validator` | Python | Consume `normalized-events`; validate + enrich; write raw vault + OpenSearch + Postgres lineage | 5, 6 |
| `api-gateway` | Python (Flask) | REST + SSE/WebSocket; RBAC/JWT; query normalized & raw events | 5, 7, 11 |
| `dashboard` | React/Tailwind | Live SOC dashboard consuming the SSE/WebSocket stream | 7 |
| `source-onboarding` | Flask | UI/API to add sources, define parsers, test, register | 8 |
| `ai-parser-generator` | Python | Optional AI-assisted parser & mapping suggestions (human-approved) | 9 |

## 4. Kafka Topics

| Topic | Key | Value | Consumers |
|-------|-----|-------|-----------|
| `raw-logs` | `source_id` | `EventEnvelope` (received) | parser-engine |
| `parsed-logs` | `event_id` | `EventEnvelope` (parsed) | normalizer |
| `normalized-events` | `event_id` | `EventEnvelope` (normalized) | validator |
| `failed-events` | `raw_event_id` | `EventEnvelope` (error) | DLQ processor |
| `schema-drift-events` | `source_id` | drift alert dict | alerting/onboarding |

## 5. Storage Layer (Phase 5)

### 5.1 Storage Architecture

```
Sources
   ↓
Ingestion
   ↓
Kafka raw-logs
   ↓
Parser
   ↓
Kafka parsed-logs
   ↓
OCSF Normalizer
   ↓
Kafka normalized-events
   ↓
   ├── MinIO       → original raw events
   ├── OpenSearch  → searchable normalized events
   └── PostgreSQL  → metadata + lineage + storage references
```

Each database has a distinct purpose:
- **MinIO**: Complete original raw payload (lossless vault)
- **OpenSearch**: Normalized/searchable event (analytics ready)
- **PostgreSQL**: Metadata + lineage + storage references (relational)

### 5.2 MinIO Raw Vault

- Stores the COMPLETE original raw payload without modification
- Object key structure: `raw-events/<date>/<source_type>/<raw_event_id>.json`
- SHA-256 integrity verification on every stored object
- Deterministic object keys for idempotent storage
- Does NOT silently overwrite existing raw events with different content

### 5.3 OpenSearch Normalized Index

- Date-based indices: `<prefix>-events-YYYY.MM.DD`
- All searchable fields indexed: event_id, raw_event_id, source_id, source_type,
  format, timestamp, event.action, severity, source.ip, destination.ip, etc.
- Lossless: `ocsf`, `parsed_fields`, and provenance data preserved
- Deterministic document IDs (event_id) for idempotent indexing

### 5.4 PostgreSQL Metadata

Tables:
- `event_metadata`: Core event information (event_id, raw_event_id, source_id,
  source_type, format, timestamps, sha256, parser_id, parser_version,
  schema_version, processing_status)
- `raw_object_metadata`: MinIO storage references (raw_event_id → object_key,
  bucket, sha256)
- `normalized_object_metadata`: OpenSearch references (event_id → index_name,
  document_id)

Foreign key constraints ensure referential integrity.

### 5.5 Idempotency

- MinIO: `raw_event_id` → object key (deterministic)
- OpenSearch: `event_id` → document ID
- PostgreSQL: Unique constraints on event_id, raw_event_id
- Duplicate Kafka deliveries do NOT create uncontrolled duplicates

### 5.6 SHA-256 Integrity Verification

- Every raw event stores its SHA-256 fingerprint
- Retrieval includes SHA-256 metadata
- Verification: retrieve raw object → recalculate SHA-256 → compare
- Clear verification result returned (verified: bool, actual: str | None)

### 5.7 Storage Services

- `RawStorageConsumer`: Kafka `raw-logs` → MinIO + PostgreSQL
- `NormalizedStorageConsumer`: Kafka `normalized-events` → OpenSearch + PostgreSQL

| System | Purpose |
|--------|---------|
| **MinIO/S3** | Raw event vault — original payload + SHA-256. Immutable object per `raw_event_id`. |
| **OpenSearch** | Normalized, searchable events for SIEM/Data-Lake/analytics consumption. |
| **PostgreSQL** | Users, RBAC, parser registry, source configuration, schema versions, event lineage index. |
| **SQLite** | Optional only for lightweight local dev/test runs. |

## 6. Integrity & Lineage (Tamper-Evident Event Provenance)

- Each raw event is fingerprinted with SHA-256.
- The raw vault stores: original payload, SHA-256, `previous_hash`,
  `current_hash` (hash chain link), and metadata.
- The lineage service verifies a normalized event's stored hash matches the
  recomputed hash of the raw vault object. A mismatch ⇒ tamper evident.
- Hash chaining is over consecutive raw events; reordering/removal is detectable.

## 7. Security

- **Auth:** JWT issued by the API gateway; `flask-jwt-extended`.
- **Roles:** `admin`, `soc_analyst`, `viewer`. Enforced in backend decorators.
- **Passwords:** `bcrypt` (scrypt option) with per-hash salt.
- **Transport:** TLS/mTLS-ready (env-configurable; disabled in local dev only).
- **Audit:** all privileged actions written to an immutable audit log.

## 8. Parser Engine & Registry

The Parser Engine is the bridge between raw ingestion and downstream
normalization. It consumes `raw-logs`, selects the appropriate parser via the
Parser Registry, and emits structured `ParsedEvent` objects to `parsed-logs`.

### 8.1 Parser Registry

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

### 8.2 Supported Formats (Phase 3)

| Format | Parser | Source |
|--------|--------|--------|
| Syslog | `FirewallSyslogParser` (`firewall_syslog_v1`) | Firewall |
| JSON | `RouterJsonParser` (`router_json_v1`) | Router |
| CEF | `IDSCEFParser` (`ids_cef_v1`) | IDS/IPS |

### 8.3 Failure Handling

Parsing failures never discard raw events. Failed envelopes are published to
`failed-events` with an `EventError` recording the stage, code, message, and
traceback. The consumer continues processing subsequent events.

## 9. OCSF-Based Normalization (Phase 4)

The Normalizer converts source-specific `ParsedEvent` structures into a common,
OCSF-aligned `NormalizedEvent` representation. This enables downstream SIEM,
Data Lake, and analytics consumers to work with a consistent schema while
preserving full source-specific information.

### 9.1 Normalization Principles

1. **Lossless preservation.** All original extracted fields are retained under
   `parsed_fields`. Normalization never deletes data.
2. **Common schema.** Source-specific field names are mapped to OCSF-aligned
   common fields (e.g. `src_ip` → `source.ip`, `action` → `event.action`).
3. **Provenance.** Every normalized event carries `raw_event_id`, `event_id`,
   `parser_id`, `parser_version`, `schema_version`, and `sha256`.
4. **Validation.** Network fields (IP, port, protocol) are validated before
   inclusion in the normalized output.

### 9.2 Field Mappings

| Source Field | Common Field | Notes |
|--------------|--------------|-------|
| `src_ip`, `src` | `source.ip` | Validated IPv4/IPv6 |
| `dst_ip`, `dst` | `destination.ip` | Validated IPv4/IPv6 |
| `src_port` | `source.port` | 0-65535 range check |
| `dst_port` | `destination.port` | 0-65535 range check |
| `protocol`, `proto` | `network.protocol` | Uppercase normalized |
| `action`, `act` | `event.action` | Mapped to allow/deny/detect/unknown |
| `severity` | `event.severity` | Mapped to low/medium/high/critical |
| `timestamp`, `rt` | `event.time` | ISO-8601 UTC |
| `host` | `device.name` | Source device identifier |
| `interface` | `device.interface` | Network interface |

### 9.3 Action Normalization

| Source Actions | Common Action |
|----------------|---------------|
| ALLOW, ACCEPT, permitted, pass | `allow` |
| DENY, DROP, blocked, block, reject, denied | `deny` |
| detected, alerted, alert, identified | `detect` |
| unknown / unmapped | `unknown` |

### 9.4 Severity Normalization

| Source Severity | Common Severity |
|----------------|-----------------|
| 0-2 (syslog) / 0-3 (CEF) | `low` |
| 3-5 (syslog) / 4-6 (CEF) | `medium` |
| 6-7 (syslog) / 7-9 (CEF) | `high` |
| 8-10 (CEF) | `critical` |
| unmapped / invalid | `unknown` |

### 9.5 OCSF-Aligned Output

Each `NormalizedEvent.ocsf` dict contains:

```json
{
  "event": {
    "category": "Network Activity",
    "class_name": "Network Activity",
    "severity": "medium",
    "action": "allow",
    "time": "2026-09-07T08:01:17+00:00"
  },
  "source": {
    "ip": "10.0.0.1",
    "port": 12345
  },
  "destination": {
    "ip": "192.168.1.1",
    "port": 80
  },
  "network": {
    "protocol": "TCP",
    "bytes": 1024
  },
  "device": {
    "name": "fw-dmz-01",
    "type": "firewall",
    "interface": "GigabitEthernet0/0"
  }
}
```

### 9.6 Unknown Field Preservation

Fields without a direct OCSF mapping remain in `NormalizedEvent.parsed_fields`
and are **never discarded**. This ensures normalization is additive and
lossless.

### 9.7 Schema Versioning

The normalized event carries `schema_version` (default `1.0.0`). Future schema
changes will introduce new versions without silently altering historical event
interpretations.

## 10. Deployment

- Docker → `docker-compose.yml` (dev).
- Kubernetes manifests in `k8s/` (Phase 12).
- Air-gapped: all images pinned; `.tar` bundles + offline build documented
  in `docker-compose.airgap.yml` and `scripts/build-airgap.sh`.

### 10.1 Air-Gapped Deployment Architecture

ULPF is designed for **fully offline operation** — no outbound internet access required at runtime.

#### Network Isolation

```
┌─────────────────────────────────────────────────────────────────┐
│                    AIR-GAPPED ENVIRONMENT                       │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Browser   │───▶│  Frontend   │───▶│    API      │        │
│  │  (External) │    │  (Nginx)    │    │  (Flask)    │        │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘        │
│                             │                   │               │
│                    ┌────────┴──────────────────┴───────┐        │
│                    │       INTERNAL NETWORK            │        │
│                    │  (docker network: ulpf-internal)  │        │
│                    │  internal: true  ← NO EGRESS      │        │
│                    ├───────────────────────────────────┤        │
│                    │  Kafka ──▶ Parser ──▶ Normalizer  │        │
│                    │    │                           │        │
│                    │    ▼                           ▼        │
│                    │  MinIO ◀── Raw Storage    OpenSearch  │        │
│                    │    │                           │        │
│                    │    └──────────▶ PostgreSQL ◀──┘        │
│                    └───────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

#### Guarantees

| Guarantee | Implementation |
|-----------|----------------|
| **No outbound connections** | `internal: true` on Docker network; verified by `scripts/verify-airgap.py` |
| **No CDN dependencies** | Frontend builds all assets locally (Vite + Tailwind); no external fonts/CDN |
| **No telemetry** | No Sentry, DataDog, OpenTelemetry, Prometheus push gateways |
| **No external API calls** | AI parser generator defaults to `heuristic` (local) provider |
| **No runtime package installs** | All Python/Node deps baked into images at build time |
| **Pinned base images** | Specific tags (not `latest`) for reproducibility |

#### Offline Build Process

1. **Build machine** (internet-connected):
   ```bash
   docker compose -f docker-compose.airgap.yml build --parallel
   docker save -o ulpf-airgap-images.tar $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "ulpf|cp-zookeeper|cp-kafka|minio|opensearch|postgres|nginx|node")
   ```

2. **Transfer** `ulpf-airgap-images.tar` to air-gapped machine via secure media.

3. **Target machine** (air-gapped):
   ```bash
   docker load -i ulpf-airgap-images.tar
   cp .env.example .env  # Configure secrets
   docker compose -f docker-compose.airgap.yml up -d
   ```

#### Verification

```bash
# Monitor for 60 seconds, fail if any non-RFC1918 destination contacted
python scripts/verify-airgap.py --duration 60
```

## License & Acknowledgements

Built for the Smart India Hackathon 2026 problem statement 26156.
