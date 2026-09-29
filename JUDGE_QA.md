# ULPF — Judge Q&A Preparation (SIH 2026)

## Technical Deep-Dive Questions

### Q1: "How does ULPF differ from Logstash / Fluentd / Vector?"
**A**: Three fundamental differences:
1. **Lossless by design** — Raw payload stored in MinIO + referenced in every NormalizedEvent (`raw_payload` field). Logstash drops raw after parsing.
2. **End-to-end provenance** — SHA-256 at ingestion + hash-chain (`previous_hash` → `current_hash`) + 2-hop lineage (raw→parsed→normalized) stored in PostgreSQL. Vector has no lineage.
3. **OCSF-native normalization** — Not just field mapping; full OCSF v1.0.0 event structure with `parsed_fields` preserving ALL original fields additively. Fluentd has no OCSF support.

### Q2: "Explain the hash-chain mechanism."
**A**: 
- At ingestion: `raw_event_id = UUID4`, `sha256 = SHA256(raw_payload_bytes)`
- Hash-chain link: `current_hash = SHA256(previous_hash + current_raw_payload)`
- Stored in EventEnvelope: `previous_hash`, `current_hash`, `sha256`
- Verification: Recompute chain from genesis → any gap = tampering detected
- Used for: Immutable audit trail, forensic integrity, compliance (evidence chain)

### Q3: "How do you handle schema evolution / new log fields?"
**A**: Two-layer approach:
1. **Additive normalization** — Unknown fields never dropped; preserved in `parsed_fields` dict alongside OCSF-mapped fields
2. **Schema Drift Detection** — Profile per source_type (field→type histogram). On ingest, compare extracted fields vs profile. New field → `SCHEMA_DRIFT` event to Kafka + dashboard alert. Admin reviews → updates profile → pipeline continues.

### Q4: "How does config-driven onboarding work?"
**A**: 
- Source config YAML defines: `source_id`, `source_type`, `parser_id`, `normalizer_id`, `kafka_topics`, `field_mappings`
- Parser registry: `ParserRegistry.lookup(envelope)` matches by `source_type` + `format`
- Normalizer registry: `NormalizerEngine._select_normalizer(envelope)` matches by `source_type`
- New source = 1 YAML file + (optionally) 1 parser class. No core code changes. Hot-reload via `/api/v1/sources` PUT.

### Q5: "What's the performance / throughput?"
**A**: 
- Async Kafka consumers (consumer groups for horizontal scaling)
- Batch writes: MinIO (multipart), OpenSearch (bulk), PostgreSQL (COPY/batched INSERT)
- Backpressure: Kafka consumer `max.poll.records` + processing_status tracking
- Benchmarks (local): ~5K EPS per parser instance; scales linearly with partitions
- Dashboard queries: OpenSearch for full-text, PostgreSQL for lineage/metadata

### Q6: "How do you ensure data integrity across services?"
**A**: 
- **At-rest**: MinIO (S3 API) + PostgreSQL (ACID) + OpenSearch (translog)
- **In-flight**: Kafka exactly-once semantics (idempotent producer + transactional consumer)
- **End-to-end**: SHA-256 in EventEnvelope verified at each stage (parser→normalizer→storage)
- **Lineage**: Every NormalizedEvent has `LineageChain` with 2 records (PARSED_FROM, NORMALIZED_FROM) + raw_event_id for raw recovery from MinIO

---

## Architecture & Design Questions

### Q7: "Why Python? Why not Go/Rust for performance?"
**A**: 
- Phase 0-8: Velocity > throughput. Python's ecosystem (Pydantic, FastAPI, Kafka clients) let us build full pipeline + dashboard + tests in 8 phases.
- Performance-critical paths (parsing, normalization) are CPU-bound but simple regex/dict ops — Python is sufficient for 5K EPS.
- Post-SIH: Hot paths can be rewritten in Rust (PyO3) or Go (gRPC) without changing contracts.

### Q8: "How do you handle multi-tenancy?"
**A**: 
- Current: Single-tenant (SIH scope). 
- Design supports: `tenant_id` field in EventEnvelope, per-tenant Kafka topics (`raw-logs-tenantA`), per-tenant MinIO prefixes, row-level security in PostgreSQL.
- Dashboard: Tenant context in JWT → filtered API queries.

### Q9: "What about encryption / secrets?"
**A**: 
- All config via environment variables (`.env` → never committed)
- MinIO: TLS + SSE-S3 encryption at rest
- Kafka: SASL_SSL
- PostgreSQL: SSL mode=require
- Secrets: External vault (HashiCorp/Vault) integration points in `config.py`

### Q10: "How does the output conversion preserve fidelity?"
**A**: 
- ConversionService takes NormalizedEvent (single source of truth)
- Each formatter maps OCSF + parsed_fields + provenance → target format
- Round-trip test: NormalizedEvent → CEF → parse → NormalizedEvent = semantic equivalence
- Original event preserved: `conversion_result.original_event_preserved = True` always

---

## SIH-Specific Questions

### Q11: "What's the blockchain connection? (Theme: Blockchain & Cybersecurity)"
**A**: 
- **Hash-chain = blockchain primitive**: Each event links to previous via `current_hash = H(prev + payload)`. Forms immutable append-only log — same structure as blockchain but without consensus overhead.
- **Provenance = audit trail**: SHA-256 + lineage = tamper-evident forensic chain for cybersecurity logs.
- **Future**: Anchor hash-chain roots to public blockchain (Ethereum/Polygon) for non-repudiation — roadmap item.

### Q12: "What's novel vs existing open-source?"
**A**: 
| Feature | Logstash | Fluentd | Vector | ULPF |
|---------|----------|---------|--------|------|
| Raw preservation | ❌ | ❌ | ❌ | ✅ |
| SHA-256 + hash-chain | ❌ | ❌ | ❌ | ✅ |
| Raw↔norm lineage | ❌ | ❌ | ❌ | ✅ |
| OCSF native | ❌ | ❌ | Partial | ✅ |
| Schema drift detection | ❌ | ❌ | ❌ | ✅ |
| Config-driven onboarding | Partial | Partial | ❌ | ✅ |
| 7 output formats | 3 | 2 | 4 | 7 |

### Q13: "Team contribution — who did what?"
**A**: 
- **Phase 0-2**: Ingestion API, Kafka, raw storage, parser engine (3 parsers)
- **Phase 3-4**: Normalizer engine (3 normalizers), OCSF mapping, validation
- **Phase 5**: Lineage models, repository, hash-chain, verification API
- **Phase 6**: Schema drift detector, profile management
- **Phase 7**: Source onboarding manager, YAML configs, Sources API
- **Phase 8**: React dashboard (Events, Sources, Schema, Lineage, Convert, Health)
- **Phase 9A**: Output conversion engine (7 formatters, ConversionService)
- **All**: 309 unit tests, CI, documentation

---

## Trap Questions & Safe Answers

| Trap Question | Safe Answer |
|---------------|-------------|
| "Does it handle 1M EPS?" | "Core pipeline scales horizontally via Kafka partitions. Current single-instance ~5K EPS. Production deployment uses 3+ parser consumers." |
| "Is AI parser gen working?" | "Phase 9B (post-SIH). Design: LangGraph few-shot → parser code → auto-register. Not in submission." |
| "Why not OpenTelemetry?" | "OTel for metrics/traces. ULPF for security logs (Syslog/CEF/LEEF) — different domain. OCSF aligns with OTel semantic conventions." |
| "Vendor lock-in?" | "Zero. All storage: MinIO (S3 API), OpenSearch (OpenSearch API), PostgreSQL (standard SQL). Output: 7 open formats." |
| "How do you test?" | "309 unit tests (hermetic). Integration tests with live infra (skipped by default). Smoke test: 60 assertions across 3 formats × 7 outputs." |

---

## Closing Statement
> *"ULPF solves the fundamental problem every SOC faces: logs in 10 formats, no provenance, no traceability. We deliver a single pipeline that preserves raw, normalizes to OCSF, chains hashes for integrity, tracks lineage for forensics, and converts to any downstream format — all config-driven, all tested, all running live today."*