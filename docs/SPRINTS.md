# Drastha implementation roadmap

## Delivery principle

Production follow-on sequence (the original sprint plan below is historical):

- Sprint 8: shared ingestion/inference/session path — complete.
- Sprint 9: measured passive metadata features — complete.
- Sprint 10: independent evaluation, provenance and split guards — complete;
  external baseline findings and limitations are in `SPRINT_10.md`.
- Sprint 11: feature-compatible labelled corpora, validation-only calibration and
  an independently reserved final holdout; no tuning on the inspected CTU run.
- Sprint 12: continuous ingestion, backpressure, checkpoints and recovery.
- Sprint 13: authentication, retention and tamper-evident evidence.
- Sprint 14: sustained end-to-end throughput and real-sensor/browser validation.
- Sprint 15: operational deployment and runbooks.

Every sprint ends with a demonstrable, testable slice. A detector is complete only when it produces the standard alert contract, includes human-readable evidence, has benign and malicious tests, and records its limitations.

## Definition of done for every sprint

- Code is reviewed and covered by automated tests.
- Inputs, outputs, thresholds, assumptions and limitations are documented.
- A repeatable demo or replay command exists.
- Measured results are separated from targets.
- No component requires a return path into the protected network.
- No private dataset, model artefact or packet capture is committed to Git.

## Sprint 0 - Foundation and first vertical slice (Week 1)

Goal: prove `Zeek JSONL -> normalized event -> recon detector -> JSON alert`.

Deliverables: Python package and tests; shared event/evidence/alert contracts; Zeek connection-log reader; sliding-window recon detector; command-line replay; synthetic fixture.

Acceptance: benign traffic raises no alert; vertical and horizontal scans have distinct subtypes; alerts contain time window, flow IDs, confidence, severity, evidence and limitations; malformed records show their line number.

Owners: network/capture, backend, QA/documentation.

## Sprint 1 - Data plane, DDoS and capture health (Weeks 2-3)

Goal: accept PCAP replay through Zeek and detect high-rate attacks.

Deliverables: reproducible Zeek configuration; PCAP adapter; generic window engine; SYN and UDP flood features; capture-loss and ingestion-delay telemetry; CICDDoS2019 data manifest.

Acceptance: one command turns PCAP into alerts; DDoS subtypes have separate evidence; replay reports throughput, P50/P95 latency and dropped events.

Owners: network/capture, streaming/backend, detection research.

## Sprint 2 - DNS analytics (Weeks 4-5)

Goal: detect DGA-like domains and DNS-tunnelling behaviour.

Deliverables: DNS adapter; lexical and n-gram features; versioned benign-domain snapshot; DNS-tunnel window features; model card; encrypted-DNS limitation.

Acceptance: DGA and tunnelling are distinct alerts; splits avoid duplicate/domain-family leakage; false positives include CDN and hosted-service examples.

Owners: ML/data, detection research, QA.

## Sprint 3 - C2 and encrypted-session metadata (Weeks 6-7)

Goal: detect repeated C2-like communication without payload decryption.

Deliverables: interval, jitter, periodicity and size-consistency features; CTU-13 holdout evaluation; TLS/QUIC metadata; fingerprint and anomaly scoring.

Acceptance: benign scheduled traffic is tested; beacon alerts explain timing evidence; fingerprints are never the sole proof of malware.

Owners: ML/data, network/capture, detection research.

## Sprint 4 - Exfiltration, correlation and scoring (Weeks 8-9)

Goal: combine detector events into incident-level stories.

Deliverables: byte-ratio, burst, rarity and baseline features; incident store; cross-detector correlation; calibrated confidence; separate severity policy; deduplication and analyst feedback.

Acceptance: approved backups do not automatically become exfiltration incidents; incidents retain every contributing detector; scores are deterministic and inspectable.

Owners: backend, ML/data, detection research.

## Sprint 5 - Analyst API and dashboard (Weeks 10-11)

Goal: provide an operational analyst workflow.

Deliverables: FastAPI service; PostgreSQL schema; React/TypeScript incident queue, evidence, timeline, health, provenance, review and export views.

Acceptance: queue-to-evidence takes no more than three interactions; confidence and severity remain separate; API and UI run offline in Docker Compose.

Owners: backend, frontend/UX, QA.

## Sprint 6 - Evaluation and hardening (Weeks 12-13)

Goal: replace assumptions with reproducible evidence.

Deliverables: per-threat quality metrics; latency/throughput/resource benchmarks; loss, skew, malformed-input and restart tests; threat model; hardened offline bundle.

Acceptance: every PPT metric links to a test; no pooled accuracy hides weak classes; missing/delayed data causes visible, safe degradation.

Owners: QA/documentation, backend, all detector owners.

## Sprint 7 - SIH submission and rehearsal (Week 14)

Goal: deliver a concise submission and resilient demonstration.

Deliverables: official six-slide deck; short and long demo scripts; live replay plus backup video; Q&A sheet; cleaned release.

Acceptance: portal metadata is verified; every claim is cited, measured or labelled as a target; demo succeeds twice offline from a clean machine.

Owners: QA/documentation and team lead, with all members rehearsed.

## Recommended six-person ownership

| Role | Main responsibility |
|---|---|
| Network/capture | Zeek, PCAP, protocols, lab and capture health |
| Streaming/backend | Contracts, windows, pipeline, queues and APIs |
| ML/data | Datasets, features, models, calibration and drift |
| Detection research | Threat logic, thresholds, correlation and evasion tests |
| Frontend/UX | Analyst workflow, dashboard and evidence visualization |
| QA/documentation | Tests, metrics, reports, demo, PPT and Q&A |

## First backlog after Sprint 0

1. Pin Zeek in a Linux container or environment.
2. Add a PCAP-to-Zeek adapter with parser provenance.
3. Extract a generic sliding-window store from the recon detector.
4. Implement capture and replay health metrics.
5. Add separate SYN and UDP flood detectors with threat cards.
6. Create the CICDDoS2019 manifest without committing data files.
