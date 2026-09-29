# ULPF — 2-Minute SIH Demo Script

## Setup (30 seconds before demo)
```bash
# Terminal 1: Start infrastructure
cd D:\Log
docker compose up -d

# Terminal 2: Start backend API
cd D:\Log\backend
python -m ulpf.api &
# Wait for "Running on http://0.0.0.0:8000"

# Terminal 3: Start frontend
cd D:\Log\frontend
npm run dev &
# Opens at http://localhost:5173
```

---

## Demo Flow (2 minutes)

### 0:00-0:15 — Ingestion & Parsing (Live)
**Terminal 1: Ingest 3 log formats via REST API**
```bash
# 1. Cisco ASA Syslog (Firewall)
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80",
    "source_id": "fw-dmz-01",
    "source_type": "firewall",
    "format": "syslog"
  }'

# 2. Cisco Router JSON
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "{\"timestamp\":\"2026-09-07T08:01:33Z\",\"src_ip\":\"10.64.65.4\",\"dst_ip\":\"172.16.194.163\",\"src_port\":45123,\"dst_port\":443,\"protocol\":\"TCP\",\"action\":\"permitted\",\"interface\":\"GigabitEthernet0/0\",\"bytes\":1024}",
    "source_id": "router-core-01",
    "source_type": "router",
    "format": "json"
  }'

# 3. Cisco IDS CEF
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP",
    "source_id": "ids-sensor-01",
    "source_type": "ids",
    "format": "cef"
  }'
```
**Say**: *"Three different vendors, three different formats — single API, automatic format detection."*

---

### 0:15-0:45 — Dashboard: Events & Provenance
**Browser: Open http://localhost:5173 → Events page**
- Show 3 events with: `event_id`, `raw_event_id`, `source_type`, `parser_id`, `sha256`
- Click first event → **Event Detail** modal
- Highlight: **Raw Payload** (original log), **OCSF** (normalized), **Parsed Fields** (lossless), **Lineage** (raw→parsed→normalized)
- Click **Lineage** tab → Visual chain with SHA-256 verification

**Say**: *"Every event carries full provenance: raw payload never lost, SHA-256 integrity, complete lineage graph."*

---

### 0:45-1:15 — Output Conversion (Live)
**Browser: Convert page (or Terminal)**
```bash
# Convert firewall event to CEF (for ArcSight)
curl -X POST http://localhost:8000/api/v1/convert \
  -H "Content-Type: application/json" \
  -d '{"event_id": "<evt-id-from-step-1>", "output_format": "cef"}'

# Convert to LEEF (for QRadar)
curl -X POST http://localhost:8000/api/v1/convert \
  -H "Content-Type: application/json" \
  -d '{"event_id": "<evt-id>", "output_format": "leef"}'

# Convert to CSV (for analysts)
curl -X POST http://localhost:8000/api/v1/convert \
  -H "Content-Type": application/json \
  -d '{"event_id": "<evt-id>", "output_format": "csv"}'
```
**Show output**: CEF header, LEEF tabs, CSV columns — all from same normalized event.

**Say**: *"7 output formats from one normalized event. No re-parsing, no data loss."*

---

### 1:15-1:45 — Source Management & Schema Drift
**Browser: Sources page**
- Show registered sources (fw-dmz-01, router-core-01, ids-sensor-01)
- Click **Add Source** → Demo YAML config (parser_id, normalizer_id, topic mapping)
- **Schema Drift page** → Show drift detection for new fields

**Say**: *"New source = 1 YAML file. Schema drift detected automatically when fields change."*

---

### 1:45-2:00 — Architecture Summary
**Browser: Health page** → All services green (Kafka, MinIO, OpenSearch, PostgreSQL)

**Say**: *"ULPF: Production-ready, standards-aligned, extensible. 309 tests passing. Ready for deployment."*

---

## Backup Commands (if live demo fails)

### Quick Smoke Test (Terminal)
```bash
cd D:\Log\backend && python smoke_test.py
# Shows: 60/60 assertions pass across all 3 formats + 7 outputs
```

### Unit Tests
```bash
cd D:\Log\backend && python -m pytest --tb=short -q
# 309 passed, 31 skipped
```

### Architecture Diagram (Browser)
Open `docs/architecture.md` or show ASCII diagram from presentation.

---

## Key Talking Points (if judges ask)

| Question | Answer |
|----------|--------|
| "Why not just use Logstash/Fluentd?" | They discard raw logs; ULPF preserves raw + adds OCSF + hash-chain + lineage in one pipeline |
| "How do you add a new log source?" | 1 YAML config + 1 parser class (inherits base). No core changes. Hot-reload supported. |
| "What about performance?" | Async Kafka consumers, batch writes to MinIO/OS/PG. Horizontal scaling via consumer groups. |
| "Is this production-ready?" | Core pipeline: yes. Dashboard: MVP. K8s: configs ready. AI features: post-SIH roadmap. |
| "How does hash-chain work?" | Each event: `current_hash = SHA256(prev_hash + current_payload)`. Tamper-evident log chain. |

---

## Demo Checklist
- [ ] Docker services running (Kafka, MinIO, OpenSearch, PostgreSQL)
- [ ] Backend API on :8000
- [ ] Frontend on :5173
- [ ] 3 test payloads ready in clipboard
- [ ] Event IDs from ingestion saved for convert demo
- [ ] Browser tabs: Events, Convert, Sources, Schema Drift, Health
- [ ] Terminal ready for curl commands