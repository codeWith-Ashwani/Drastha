# Drastha build status

Last updated: 4 September 2026

## Production roadmap update

Sprint 16's integrity-preserving optimization slice is delivered with **334
Python tests passing** (20 new). Continuous incident/alert/report publication is
atomic; redundant normalization and state scans are removed without bypassing
verification. The finite signed profiler run is about 23% faster. Signed 100
records/sec for 60 seconds passes (6,000 records, P95 107.15 ms); default-64 and
explicit batch-256 1,000 records/sec runs both fail at least one unchanged gate.
Mixed upload/API/restart parity remains 452 accepted, 8 TP, 0 FP/FN, 86 TN, healthy;
real loopback HTTPS backup/restore passes. See `docs/SPRINT_16.md` for raw reports
and boundaries. Default batch, detector thresholds and quality checks are
unchanged. Checkpoint migration, compaction and general production capacity
remain open. Existing engine-mismatched journals still fail closed.

Sprint 15's protected local operations/recovery slice is delivered with **314
Python tests passing**. Read-only preflight, create-only signed SQLite backup and
restore, selected-head verification, and a loopback HTTPS launcher are implemented.
A real verifying HTTPS client passed the disposable upload/backup/restore drill;
mixed replay remains 452 accepted, 8 TP, 0 FP/FN, 86 TN and healthy. See
`docs/SPRINT_15.md` and `docs/OPERATIONS_RUNBOOK.md`. No existing service or live
database was changed. Remote deployment, host ACL/encryption, OS supervision,
real sensor/browser validation and coordinated stream recovery remain open;
local TLS success is not a production-deployment certificate.

Sprint 14's paced-load and sensor-check tooling slice is delivered with **283
Python tests passing**. Signed continuous ingestion -> SQLite -> actual analyst
ASGI API processed 6,000 records at an offered 100 records/sec for 60 seconds,
healthy with zero rejections and P95 visibility 137.11 ms. The 1,000 records/sec
signed stress run **failed** (5,484 of 60,000 inputs remained unobserved at the
drain deadline); its failure report is retained. No detector/quality/security
checks were weakened. See `docs/SPRINT_14.md` for exact boundaries and results.
Real Zeek validation is blocked by the missing native/WSL installation; browser
approval, real TLS transport, all-protocol/long-duration capacity and scaling
remain open. This is not a fully completed production-validation milestone.

Sprint 13's protected-access/signed-evidence slice is delivered with 267 Python
tests passing. Opt-in HTTPS-only role-based credentials, authenticated review
identity, HMAC chain/current-state verification, export receipts and admin-only
completed-report retention/holds are implemented for SQLite. The local demo is
unchanged and security was not enabled on the running installation. Protected
HTTP mixed replay still yields 452 accepted, 8 TP, 0 FP/FN, 86 TN and healthy
quality. See `docs/SPRINT_13.md`: identity lifecycle, external audit anchoring,
full evidence retention/encryption and production-load validation remain open.

Sprint 12's bounded single-file continuous-ingestion/recovery slice is delivered:
read-only JSONL follower, bounded batches, durable SQLite journal, strict late and
duplicate quarantine, verified detector-state reconstruction and idempotent analyst
projection. 240 Python tests pass, including abrupt child-process termination and
HTTP mixed-fixture parity (452 accepted, 8 TP, 0 FP/FN, 86 TN, healthy). See
`docs/SPRINT_12.md` for measured results and limits. This is not unbounded production
streaming: compaction, rotation handoff and sustained capacity remain open.

Sprint 11's DGA corpus/threshold-selection research slice is delivered with 216
tests passing. Public UMUDGA data: 21,958 domains, family-separated train,
validation and reserved test, pinned PSL grouping and frozen candidate hashes.
The final 4,016-domain upload-path evaluation has 18 TP / 0 FP / 1,982 FN /
2,016 TN (0.9% recall), healthy telemetry and exact classifier/upload parity.
The research model failed validation and final recall gates and was **not
promoted**. Demo defaults/model/452-record results remain unchanged. Full
production calibration, operational-service captures and probability calibration
are still pending; see `docs/SPRINT_11.md`. Do not describe the entire calibration
roadmap as finished or treat zero observed FP as production readiness.

Sprint 10 independent evaluation and dataset controls are complete. The offline
corpus runner pins source/label hashes, audits splits and evaluates through the
shared analysis path. 196 tests pass. See `docs/SPRINT_10.md` for exact scope.
An actual CTU-13 scenario-11 run exposed weak coverage: 0 malicious-flow TP,
15 verified-normal flow-unit FP, 8,164 FN, 2,694 TN; 96,378 unknown units were
not relabelled benign. Input quality is genuinely degraded by 275 unsupported
records. These results are retained, not tuned away. Original demo metrics
remain healthy and unchanged; feature-compatible calibration is Sprint 11.

Sprint 9 measured passive feature implementation is complete: supported classic
PCAP headers/JA3, causal sequence baselines and prevalence, explicit network
boundaries, service-aware UDP response analysis, causal DNS evidence, and visible
feature coverage. Demo compatibility is labelled separately from derived mode.
See `docs/SPRINT_9.md` for configuration, supported formats and limitations.
Full suite: 168 passed (26 new); separate mixed replay check and frontend build
passed. The 452-record fixture retains 8 TP, 0 FP/FN, 86 TN and healthy quality.
Independent calibration and sustained production-load validation remain future work.

Sprint 8 implementation and acceptance verification are complete: HTTP upload,
streamed replay, CLI and PCAP-derived logs share normalization and detector
execution, with event-time TLS context, common finalization and durable provenance.
142 tests and the frontend build pass. See `docs/SPRINT_8.md` for the acceptance
matrix, intentional behaviour changes and remaining production-sprint boundaries.
Git author identity is confirmed as codeWith-Ashwani using its private GitHub email.

The older sprint checklists below are historical snapshots. In particular,
persistent storage listed as pending under Sprint 4 was subsequently delivered
under Sprint 5; dataset calibration and production hardening remain outstanding.

## Overall

- Sprint 0: complete
- Sprint 1: complete; real PCAP processed through Zeek 8.0.10 in WSL
- Sprint 2: demonstrable prototype complete; production dataset calibration remains future work
- Sprint 3: demonstrable prototype complete; CTU-13 holdout acquisition remains future work
- Sprint 4: demonstrable prototype complete; persistent storage and calibration remain future work
- Sprint 5: complete; SQLite and PostgreSQL/Docker deployment paths verified
- Demo UI sprint: complete; judge-facing attack story and responsive investigation view verified
- Demo reliability sprint: complete; preflight, safe reset and one-command SQLite fallback verified
- Sprint 6 demo hardening: safe telemetry degradation and full rehearsal complete
- Sprint 7 demo package: walkthrough and recovery guide complete; submission media remains later work
- Judge-day audit: fresh `.venv` setup, dependency install, frontend build,
  two-pass rehearsal and exact PowerShell launcher verified end to end
- Judge-visible pipeline: seven measured top-level stages reveal sequentially;
- Near-real-time objective path: 67 simulated passive connection, DNS, and TLS
  metadata records are streamed individually to the dashboard; ten labelled
  findings spanning every required threat family appear during processing and
  persist as eight risk-scored incidents without any return path to the monitored
  network.
  detector internals remain abstracted while counts, status and timing stay visible

## Limitation burn-down

- [x] Limitation 1: removed the manual correlation-to-database import step.
- [x] `correlate-alerts` now persists automatically when `--database` or
  `DRASTHA_DB` is configured.
- [x] Verified against PostgreSQL in Docker: 2 alerts produced 1 critical incident.
- [x] Reprocessing remained idempotent and preserved the analyst's `investigating` status.
- [x] Limitation 2: exfiltration baselines, active windows, and cooldowns persist across restarts.
- [x] Limitation 3: correlation restores prior alerts and merges related alerts across separate runs.

## Sprint 0 acceptance checklist

- [x] Python package and repository structure
- [x] Shared `NetworkEvent`, `Evidence` and `Alert` contracts
- [x] Zeek `conn.log` JSONL parsing and normalization
- [x] Line-numbered validation errors
- [x] Vertical port-scan detection
- [x] Horizontal host-scan detection
- [x] Sliding-window expiry
- [x] Alert cooldown/deduplication
- [x] Confidence, severity, flow IDs, evidence and limitations
- [x] Command-line replay
- [x] Synthetic scan fixture
- [x] Seven automated tests passing
- [x] Saved end-to-end demo alert

## Verified commands

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH = "src"
drastha replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5
```

## Current limitations

- Zeek JSONL replay and raw-PCAP processing are fully verified. The real sample capture produced 12 normalized connection events through the Windows-to-WSL adapter.
- Reconnaissance, SYN-flood and UDP-flood behaviour are implemented. UDP reflection/amplification attribution still needs service-aware directional features.
- Thresholds are configuration values, not yet learned from a benign baseline.
- Confidence is transparent but not calibrated on labelled datasets yet.
- Multi-user authentication and production traffic capture remain outside the demo scope.

## Sprint 1 acceptance checklist

- [x] Reusable keyed sliding-window engine
- [x] Bounded out-of-order event support
- [x] SYN-flood detector with incomplete-connection ratio
- [x] UDP-flood detector using packet and byte volume
- [x] Separate evidence and limitations per DDoS subtype
- [x] Replay health: count, event span, ordering and processing rate
- [x] Capture-loss visibility reported honestly when unavailable
- [x] PCAP-to-Zeek subprocess adapter
- [x] Zeek availability command and actionable error
- [x] CICDDoS2019 dataset manifest and leakage-safe split policy
- [x] Eighteen total automated tests passing
- [x] Saved Sprint 1 alerts and health report
- [x] Windows-to-WSL Zeek bridge and real Zeek readiness check
- [x] Real PCAP-to-Zeek-to-detectors execution using `/home/shukl/zeek-test/sample.pcap`

## Next sprint

## Sprint 2 acceptance checklist

- [x] Separate Zeek DNS event adapter with line-numbered validation
- [x] Lexical features: length, labels, digits, hyphens, vowels, uniqueness and entropy
- [x] Character 3-gram feature pipeline and inspectable Naive Bayes model
- [x] Duplicate-domain and malicious-family leakage checks
- [x] DNS-tunnelling sliding-window features
- [x] Distinct DGA-like and DNS-tunnelling alert subtypes
- [x] CDN and hosted-service benign holdout examples
- [x] Allowlist support
- [x] Encrypted-DNS limitation in reports and alerts
- [x] Versioned benign-snapshot manifest and synthetic demonstration fixture
- [x] Generated model artifact, metrics and model card
- [x] Synthetic replay: 21 events, 2 expected alerts
- [x] Real sample replay: 7 DNS events, 0 alerts
- [x] Twenty-seven total automated tests passing
- [ ] Production dataset acquisition, licence review and calibration

## Next sprint

## Sprint 3 acceptance checklist

- [x] Per-endpoint repeated-connection windows
- [x] Mean interval, jitter, periodicity and size-consistency features
- [x] Periodic C2-like beacon alert with inspectable evidence
- [x] Zeek TLS and generic QUIC metadata adapter
- [x] Server-name, version, cipher, ALPN and fingerprint context
- [x] Contextual encrypted-session anomaly score
- [x] Fingerprints prohibited as sole alert triggers
- [x] Benign irregular scheduled-traffic and variable-transfer tests
- [x] Destination allowlist support
- [x] CTU-13 scenario-holdout manifest
- [x] Synthetic replay: 8 connections, 8 TLS records, 1 expected alert
- [x] Real sample replay: 12 connections, 2 TLS records, 0 alerts
- [x] Thirty-five total automated tests passing
- [ ] CTU-13 dataset acquisition, licence review, scenario evaluation and calibration

## Next sprint

## Sprint 4 acceptance checklist

- [x] Outbound volume, direction ratio and per-source baseline features
- [x] Recently observed destination context without novelty-only alerting
- [x] Approved backup destination suppression
- [x] Balanced-download benign test
- [x] Evidence-rich outbound-volume anomaly alert
- [x] Time- and source-based cross-detector incident correlation
- [x] Every contributing alert and detector retained
- [x] Deterministic risk-score components separated from confidence
- [x] Alert-ID deduplication and idempotent replay
- [x] Validated analyst-feedback contract
- [x] Synthetic exfiltration replay: 8 events, 1 alert
- [x] C2 plus exfiltration: 2 alerts, 1 critical incident, score 100
- [x] Forty-two total automated tests passing
- [ ] Persistent incident store, production baselines and policy calibration

## Next sprint

## Sprint 5 acceptance checklist

- [x] FastAPI service with generated OpenAPI contract
- [x] Persistent incident, alert, status, and feedback repository
- [x] SQLite local mode for a low-friction offline demonstration
- [x] PostgreSQL schema and repository adapter
- [x] Risk-prioritized incident queue with search and severity filter
- [x] One-click queue-to-evidence workflow
- [x] Attack timeline and evidence/provenance views
- [x] Confidence displayed separately from policy severity and risk score
- [x] Analyst status and disposition workflow
- [x] Portable JSON incident export
- [x] Responsive React/TypeScript dashboard production build
- [x] Docker Compose topology for API, dashboard, and PostgreSQL
- [x] Local smoke test: healthy API, 1 incident, 2 alerts, risk score 100
- [x] Fifty-five total automated tests passing
- [x] Docker Compose runtime verification with a healthy PostgreSQL container
- [x] Containerized API verified in PostgreSQL mode with persistent demo import
- [x] Containerized dashboard returned HTTP 200 on `127.0.0.1:8000`
- [x] Incident survived separate API and PostgreSQL container restarts
- [x] Correlation automatically persists alerts and incidents to SQLite/PostgreSQL
- [x] Re-import preserves analyst status and does not create duplicates
- [x] Drastha judge-facing hero and C2-to-exfiltration attack-chain narrative
- [x] Capture-relative timestamps replace misleading 1970 dates in synthetic demos
- [x] Evidence grouped by contributing detector with visible threshold context
- [x] Desktop and 390px mobile layouts visually verified
- [x] Required-versus-optional demo preflight with machine-readable report
- [x] Safe, repeatable reset restricted to SQLite databases inside `output/`
- [x] One-command API and dashboard start with a Docker-independent fallback
- [x] Fresh demo preparation loads 1 critical incident, 2 alerts and 1 feedback record
- [x] Fifty-nine total automated tests passing
- [ ] Authentication and role-based access control before multi-user deployment

## Next sprint

## Sprint 6 acceptance checklist

- [x] One-command reproducible evaluation report
- [x] Reconnaissance, DDoS, DNS, C2 and exfiltration reported separately
- [x] Expected and observed alert subtypes recorded per threat family
- [x] Detector-only median latency and throughput measured over 250 iterations
- [x] Scope explicitly excludes production accuracy and end-to-end performance claims
- [x] Sixty-two total automated tests passing
- [x] Missing, corrupt and excessive-error telemetry states are visible
- [x] Out-of-order records and maximum backward timestamp skew are measured
- [x] One bad record can be quarantined while valid telemetry continues safely
- [x] Excessive corruption blocks the scenario instead of producing misleading output
- [x] UI Replay Attack control runs parsing, C2 detection, exfiltration detection,
  incident correlation and persistence—not a saved-result-only animation
- [x] Clean rehearsal runs the attack twice and verifies idempotent 1-incident/2-alert state
- [x] Sixty-nine total automated tests passing
- [ ] End-to-end latency and resource benchmark with Zeek and persistence
- [ ] Formal threat model and security hardening checklist

The required SIH demonstration path is complete. Remaining items are production
hardening or final submission assets rather than blockers for the offline demo.

The final operator script and narration are in `docs/FINAL_JUDGE_DEMO_GUIDE.md`.
