# Drastha build status

Last updated: 9 September 2026

## Production roadmap update

Sprint 29 is complete. A deterministic, bounded hashed character/lexical logistic
classifier was evaluated with three family-blocked folds across all 87,829 UMUDGA
v3 domains. It reaches 80.77% development recall at threshold 0.50 but 6.96% FPR;
at threshold 0.90 FPR falls to 0.52% while recall falls to 52.47%. No operating
point passes all unchanged gates. Because every UMUDGA family has now been
inspected, the report is explicitly non-promotable and the runtime model remains
unchanged. See `docs/SPRINT_29.md`.

Sprint 28 is complete. A new official UMUDGA family-separated experiment uses
87,829 unique domains and predeclared hybrid n-gram/lexical variants. The frozen
candidate passed validation (88.75% recall, 0.625% FPR) but failed its untouched
final holdout (34.50% recall, 0.583% FPR), driven by 20.37% Vawtrak recall. Upload
parity is exact and quality is healthy. Checksum-bound promotion rejects the model,
creates no deployable artifact and leaves the demo/deployment configuration
unchanged. See `docs/SPRINT_28.md`.

Sprint 24 is complete. The actual continuous worker, derived features, signed
SQLite projection and authenticated API sustained a deterministic connection /
DNS / TLS mix at 50 input records/sec for 60 seconds: 3,000 accepted and observed,
zero rejected/backlogged, healthy quality, 111.25 ms visibility P95 and 79.85 MiB
sampled peak RSS. Two 100 records/sec attempts observed all 6,000 records but
failed the unchanged 100 ms maximum producer-lag gate, so that rate remains
undemonstrated. See `docs/SPRINT_24.md`.

Sprint 23 is complete. Protected deployment can now load one fail-closed,
checksum-linked contract for explicit monitored CIDRs, context policy, passive
safety constraints and confidence semantics. Dual boundary authorities,
overlapping CIDRs, policy tampering, unsafe constraints and unapproved DNS models
are rejected. Alerts and provenance explicitly state that confidence is a
heuristic evidence score, not a calibrated probability. The staged profile is
still not production-ready. Verification passes with 408 Python tests, 18
frontend tests and the production dashboard build; see `docs/SPRINT_23.md`.

Sprint 22 is complete. A metadata-only Slow HTTP connection-exhaustion subtype
closes the lab false negative, and checksum-pinned operator context removes the
three known contextual false positives without suppressing any of the nine attack
controls. The 392-record shared-path result moves from 9 TP / 3 FP / 0 FN / 2 TN
with empty context to 9 TP / 0 FP / 0 FN / 5 TN with context; every capture is
healthy. This small deterministic result is not a production accuracy claim.
See `docs/SPRINT_22.md`.
Current verification: **402 Python tests**, **18 frontend tests**, and the
dashboard production build pass.

Sprint 21's DGA research iteration is delivered but not production-approved.
The family-separated validation candidate reached 71.35% recall and 0.91% point
FPR, while its 95% FPR upper bound remained 1.19%. On the first frozen final
holdout it achieved 42.60% recall and 1.13% FPR, with exact upload-path parity
and healthy quality. The failed candidate cannot be loaded by normal runtime.
Verification passes with 396 Python tests, 18 frontend tests and the production
dashboard build. See `docs/SPRINT_21.md`.

Sprint 20 is complete. The SIH-guided offline lab corpus contains 13 isolated
captures and 392 healthy chronological records with checksum-pinned sidecar
truth. The shared analysis path detects eight supported attacks while preserving
three contextual false positives and one Slow HTTP false negative as explicit
historical Sprint 22 hardening targets. Verification passes with 393 Python tests, 18
frontend tests and a production dashboard build. See `docs/SPRINT_20.md`.

Sprint 19 closes the real offline sensor gate with Zeek 8.0.10 in Ubuntu 24.04
WSL. A deterministic mixed SYN/DNS/TLS PCAP produces actual `conn.log`,
`dns.log`, and `ssl.log`; 10 records are accepted, zero rejected, quality is
healthy, measured JA3/packet sequences are joined, and the completed run is read
back through the dashboard API. All 16 sensor/passivity/evidence gates pass and
detector network attempts remain zero. Existing Zeek output is now create-only:
non-empty evidence directories are refused. This is an offline interoperability
proof, not live-mirror, QUIC, accuracy or throughput validation. See
`docs/SPRINT_19.md` and `output/sprint19_sensor_integration.json`. Current
verification: **390 Python tests**, **18 frontend tests**, and the dashboard
production build pass.

Sprint 18 delivers completed-replay SIEM JSON/NDJSON export. The actual protected
upload/export drill preserves all eight incident behaviors for both corrected
fixtures (153 and 452 accepted, zero rejected, zero FP/FN, healthy). Stable event
IDs support repeated-import deduplication; signed-store receipts verify the full
export. No external delivery or vendor mapping is claimed. See `SPRINT_18.md`.
Current verification: **388 Python tests**, **18 frontend tests**, dashboard
production build and all 28 fixture/export acceptance gates passed.

Sprint 17's same-engine coordinated recovery slice is delivered (362 tests at
that release). Subsequent accuracy/evidence/dashboard work raised the baseline
to 376 tests and added recorded incident conclusions, exact run-scoped evidence,
measured TLS fixture coverage, operational context and an overall replay risk.
The corrected eight-incident fixture scores 88/100 under the documented priority
policy. Historical test counts below describe their releases, not today's suite.

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
That release's real Zeek validation was blocked by the missing native/WSL
installation; Sprint 19 later closes the offline connection/DNS/TLS sensor gate.
Browser transport, live mirror, QUIC and long-duration mixed capacity remain open.

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
