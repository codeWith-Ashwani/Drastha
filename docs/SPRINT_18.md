# Sprint 18 — monitoring-side SIEM export

## Delivered scope

Completed replays can be downloaded as versioned Drastha JSON or NDJSON for a
monitoring-side SIEM importer. Each exported event retains one incident, its
conclusion and every referenced alert/measurement from that saved run. The
manifest retains quality, coverage, context-policy counts, provenance and overall
risk. The format is `drastha-siem-export-v1`; no CEF, ECS or STIX compatibility is
claimed. Export does not initiate network delivery or mitigation.

## Operator workflow

1. Upload a replay and open **Review full evidence**.
2. Select **Download SIEM NDJSON**. This exports the whole saved run regardless
   of the individual-incident filter currently selected in the evidence dialog.
3. Configure the monitoring-side importer according to the contract below.
   Retain the original export and receipt alongside imported events.

API:

```text
GET /api/analysis-runs/{run_id}/export?format=json
GET /api/analysis-runs/{run_id}/export?format=ndjson
```

The default is JSON. Existing authentication applies: local-demo mode is unsigned;
protected mode requires HTTPS and configured credentials, allows viewer downloads,
verifies the signed SQLite store, and issues an audited HMAC export receipt.
Keys remain in the monitoring enclave. Download headers disable caching and use
a digest-based filename. Source names cannot inject HTTP headers.

## Export contract

JSON has exactly three top-level keys: `manifest`, `events`, `integrity`.

| Field | Meaning |
|---|---|
| `manifest.format` | Versioned Drastha contract identifier |
| `manifest.run_id` | Selected saved analysis run |
| `manifest.snapshot_sha256` | SHA-256 of the complete saved report serialized as sorted compact JSON |
| `manifest.event_count`, `alert_count` | Exact exported incident and alert totals |
| `manifest.scope` | `completed_run_snapshot` |
| `manifest.quality`, `feature_coverage`, `context_policy` | Original telemetry quality, missing evidence and operator-policy context |
| `manifest.overall_risk` | Original aggregate priority, or null for older runs without it |
| `manifest.analysis_provenance` | Original engine/model/profile information |
| `events[].event_id` | Stable SHA-256 identity over format, run ID, snapshot digest and incident ID |
| `events[].incident_id`, `run_id`, `snapshot_sha256` | References back to the exact saved evidence |
| `events[].observed_start`, `observed_end` | Original source seconds, including relative capture times when supplied |
| `events[].source_ip`, `destination_ips` | Observed addresses, without role or attribution assumptions |
| `events[].severity`, `risk_score`, `confidence` | Incident priority and detector confidence; no probability conversion |
| `events[].incident`, `alerts` | Complete original incident and its referenced alerts, including conclusion and limitations |
| `integrity` | Existing Drastha HMAC receipt in signed mode, otherwise null |

NDJSON line 1 is `{"record_type":"manifest","manifest":{...},"integrity":...}`.
Each following line is `{"record_type":"incident","event":{...}}`. Consumers
must route the first line as metadata, not as another incident. A benign replay
has one manifest line and zero incident lines. Eight incidents produce nine lines.
Strings are JSON escaped; embedded newlines cannot create extra events.

To verify a signed download, reconstruct `{"manifest": ..., "events": [...]}`
and verify its receipt using the existing `AuditedIncidentRepository.verify_export`
contract. This is the same canonical payload for either serialization. Receipts
include an audit head and can differ across downloads, while event IDs stay stable.
Preserve all fields and original number types when verifying the receipt. Do not
give a downstream SIEM the signing key merely to ingest data: verification can
remain in a trusted enclave-side importer. HMAC is shared-key integrity, not a
public signature or encryption.

An importer can deduplicate repeated exports by `event_id`. A new upload or a
changed snapshot deliberately changes IDs even if an incident ID is reused.
This handles repeat imports; it does not promise transport acknowledgement or
exactly-once delivery. Analyst edits made later in the global incident queue do
not change the historical run export.

## Validation and error behavior

- Missing run: 404. Invalid serialization query: 422.
- Incomplete runs, malformed references, duplicate identities, orphan alerts,
  inconsistent sources, invalid numeric values or exceeded export limits: 409.
- Signed-store tampering: 503 through the existing integrity handler.
- A degraded completed run remains degraded in the export; findings are not
  suppressed or quality relabelled. Missing evidence remains visible.
- Snapshot limit: 16 MiB canonical JSON, 5,000 incidents, 20,000 alerts. Limits
  reject the complete export; evidence is not silently truncated. Repository
  loading and serialization are in-memory and are not an unlimited export stream.
- Exports contain observed addresses and evidence. Keep operational exports
  outside Git; `output/exports/` is ignored as a suggested local destination.

## Verification

Final suite: **388 Python tests passed in 33.918 seconds** (12 new SIEM tests),
**18 frontend tests passed**, and the production TypeScript/Vite build passed.
Existing Starlette TestClient deprecation and test HMR-port warnings remain;
they did not fail validation. Browser interaction testing was not performed.

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -p test_siem_export.py -v
.venv\Scripts\python.exe scripts/check_siem_export.py --report-output output/sprint18-check-new.json
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The disposable protected API drill is retained at
[`output/sprint18_siem_export.json`](../output/sprint18_siem_export.json).
Both fixtures pass all 14 gates: authentication, exact evidence, JSON/NDJSON
equivalence, both receipts, tampered-export refusal, stable IDs, expected record
and behavior counts, healthy quality, preserved risk, source and saved snapshot.

| Fixture | Accepted/rejected | Exported incidents | TP/FP/FN/TN | Quality | Overall risk |
|---|---:|---:|---|---|---|
| Accuracy v2 | 153/0 | 8 | 8/0/0/107 | healthy | 88/100 |
| Mixed v3 | 452/0 | 8 | 8/0/0/86 | healthy | 88/100 |

Measured JSON export latency in the drill was 23.291 ms and 27.244 ms respectively.
These are small synthetic ASGI measurements, not production SIEM, TCP/TLS, browser
or sustained-load validation. Model accuracy and the failed 1,000-records/sec
capacity gate retain their existing limitations.

## Upgrade boundary and next work

The complete Python source tree participates in the continuous-ingestion engine
digest. This module changes that digest. Keep the original release for old
journals and recovery bundles; cross-version recovery still refuses mismatches.
No migration, automatic cutover or digest rewriting is introduced.

Next planned slices: Sprint 19 — profile and address the sustained-ingestion
capacity gate; Sprint 20 — define and implement a bounded source-rotation contract
with evidence continuity and restart tests. Vendor-specific SIEM mappings,
delivery queues/acknowledgements and external recipient configuration remain open.
