# ULPF — Universal Log Pre-processing Framework
## SIH 2026 Presentation (5 Slides)

---

### Slide 1: Problem & Solution

**Problem Statement (PS ID: 26156)**
- Organizations ingest logs from 10+ heterogeneous sources (firewalls, routers, IDS, servers, apps)
- Each source uses different formats: Syslog, JSON, CEF, LEEF, XML, CSV, custom
- No unified pipeline → blind spots, lost context, compliance gaps
- Existing tools discard raw logs → forensic traceability broken

**ULPF Solution**
> **Universal Log Pre-processing Framework** — Single pipeline that parses, normalizes, preserves, and converts *any* log format with end-to-end provenance.

**Key Differentiators**
- ✅ **Lossless**: Raw payload never discarded (stored in MinIO + referenced in every event)
- ✅ **Traceable**: SHA-256 + hash-chain + full lineage (raw → parsed → normalized → output)
- ✅ **Extensible**: Config-driven source onboarding — new parser = YAML, not code
- ✅ **Interoperable**: 7 output formats (JSON, CEF, LEEF, XML, CSV, Syslog, OCSF)
- ✅ **Standards-aligned**: OCSF normalization for downstream SIEM/XDR compatibility

---

### Slide 2: Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  INGESTION  │───▶│   PARSER    │───▶│   NORMALIZER    │───▶│  STORAGE LAYER   │
│   (REST)    │    │   ENGINE    │    │   (OCSF v1.0)   │    │  (MinIO/OS/PG)   │
└─────────────┘    └─────────────┘    └─────────────────┘    └──────────────────┘
       │                  │                    │                       │
       ▼                  ▼                    ▼                       ▼
  Raw Event ID      Parser ID +           OCSF Event +            Raw payload
  SHA-256 hash      Version +             Parsed Fields +         Lineage records
  Hash-chain        Extracted Fields      Schema version          Schema drift
       │                  │                    │                       │
       └──────────────────┴────────────────────┴───────────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │ OUTPUT ENGINE   │
                          │ (7 formats)     │
                          └─────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │  DASHBOARD      │
                          │ (React + API)   │
                          └─────────────────┘
```

**Core Principles**
1. **Immutability**: Raw event ID + SHA-256 assigned at ingestion; never changes
2. **Additive Normalization**: OCSF mapped fields + ALL original fields in `parsed_fields`
3. **Config-Driven**: New source = 1 YAML config + 1 parser class (no core changes)
4. **Phase-Gated**: 0-8 completed; Phase 9A (output engine) done; 9B/9C deferred to post-SIH

---

### Slide 3: Live Pipeline Demo (3 Formats)

**Input 1: Cisco ASA Syslog (Firewall)**
```
<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP 
src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)
```
→ Parsed by `firewall_syslog_v1` → Normalized to OCSF Network Activity
→ SHA-256: `a1b2c3d4...` → Lineage: raw → parsed → normalized

**Input 2: Cisco Router JSON**
```json
{"timestamp":"2026-09-07T08:01:33Z","src_ip":"10.64.65.4",
 "dst_ip":"172.16.194.163","action":"permitted","interface":"GigabitEthernet0/0"}
```
→ Parsed by `router_json_v1` → OCSF + custom `interface`/`bytes` preserved

**Input 3: Cisco IDS CEF**
```
CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|
rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP
```
→ Parsed by `ids_cef_v1` → OCSF severity=critical, action=deny, signature_id=1000

**All three**: Same pipeline, same provenance model, same output formats.

---

### Slide 4: Output Conversion Engine (Phase 9A)

| Format | Use Case | Key Features |
|--------|----------|--------------|
| **JSON** | API consumers, ML pipelines | Full event + provenance + OCSF |
| **CEF** | ArcSight, legacy SIEMs | Proper escaping, vendor/product |
| **LEEF** | IBM QRadar | Tab-delimited, key=value pairs |
| **XML** | Enterprise integrations | Valid XML, escaped entities |
| **CSV** | BI tools, spreadsheets | Dynamic headers, RFC 4180 |
| **Syslog** | Log forwarders | RFC 5424, priority calculation |
| **OCSF** | Modern SIEM/XDR | Full OCSF + provenance block |

**Conversion Service API**
```bash
POST /api/v1/convert
{"event_id": "evt-123", "output_format": "cef"}
→ Returns converted payload + metadata (formatter_id, event preserved)
```

**Verification**: All 7 formats tested in smoke test — 60/60 assertions pass.

---

### Slide 5: Submission Readiness

| Checkpoint | Status | Evidence |
|------------|--------|----------|
| **Core Pipeline** | ✅ Complete | 3 parsers, 3 normalizers, end-to-end |
| **Lossless Preservation** | ✅ Verified | Raw payload in every NormalizedEvent |
| **SHA-256 + Hash-Chain** | ✅ Verified | `sha256` field + `previous_hash`/`current_hash` |
| **Lineage (raw↔norm)** | ✅ Verified | 2-hop chains stored in PostgreSQL |
| **Schema Drift Detection** | ✅ Implemented | Profile comparison + drift events |
| **Config-Driven Onboarding** | ✅ Implemented | YAML source configs + parser registry |
| **Output Conversion (7 fmt)** | ✅ Phase 9A done | All formatters + ConversionService |
| **Dashboard (React)** | ✅ Phase 8 done | Sources, Schema, Lineage, Events, Convert |
| **Unit Tests** | ✅ 309 passing | `pytest` green |
| **Lint/Typecheck** | ✅ Clean | `ruff` + `mypy` (core) pass |

**Next Steps (Post-SIH)**
- Phase 9B: AI-assisted parser generation (LangGraph + few-shot)
- Phase 9C: Explainable anomaly detection (IsolationForest + SHAP)
- Kubernetes deployment hardening

**Team**: NTRO | Theme: Blockchain & Cybersecurity | Category: Software
**PS ID**: 26156 | **Repo**: ULPF Universal Log Pre-processing Framework