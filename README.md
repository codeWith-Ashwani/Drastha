# Drastha

**Passive AI-assisted cyber-threat intelligence for one-way IP networks.**

Drastha watches network metadata without sending packets back to the protected
network. It detects suspicious behaviour, gives every finding a clear label and
confidence score, connects related findings into incidents, calculates an
investigation priority, and shows the supporting evidence on a dashboard.

The repository contains a working offline SIH demonstration and a production
hardening track. Controlled replay results are reproducible; real-traffic
generalization, continuous-service scale and operational deployment remain open.

## SIH26145 dataset and traffic-tool provenance

The finite SIH-only delivery gates and stop condition are in
[SIH closure plan](docs/SIH_CLOSURE_PLAN.md).

**Current follow-up (16 September 2026):** [Sprint 38 independent CTU DGA
evaluation](docs/SPRINT_38.md) freezes 2,000 DGA and 2,000 benign names from the
official DNS Threats test split before inference. The deployed demo model reached
8.95% recall / 1.65% FPR. A new candidate trained only on the official training
split passed internal validation, then reached **68.8% recall / 0.1% FPR** on the
frozen upload-path holdout. It missed the unchanged 70% recall gate and was not
deployed. This is a measured improvement, not a passing accuracy claim.

The earlier [DGA/TLS validation follow-up](docs/SIH_VALIDATION_FOLLOWUP.md)
adds a genuine PCAP-derived TLS size/timing-positive control (4 attributed TP,
0 FP across 114 benign sessions) and two DNS campaign-context controls, including
a frozen external Kraken/Alexa sample (1 behaviour TP, 0 FP, 2 TN). A separate
domain-only candidate reached 82% recall but **2% FPR** on its small external
sample, above the 1% gate, so it was not deployed. The original 40/40 Vawtrak
domain-only miss remains. The final gate verifies the functional prototype but
does **not** promote a new SIH release while that generalization gap remains.

[Sprint 36 fresh-source validation](docs/SPRINT_36.md) now checks separate,
checksum-frozen `iperf3`, `hping3`, Slowloris-mode, iodine, C2-emulator,
published-DGA and real-TLS sessions. Flow and metadata lab behaviours passed;
the deployed DGA model missed 40/40 published Vawtrak domains, and six changed
TLS sessions did not have the independent packet-size/timing anomaly needed for
an alert. These failures are retained as SIH acceptance evidence, not folded
into the controlled 452-record score.

The [Sprint 37 final acceptance audit](docs/SPRINT_37.md) recorded its historical
458-test baseline and both then-open gaps. The subsequent follow-up closes the
measured TLS-positive lab gap, while retaining the failed DGA model-promotion gate.

The problem statement's dataset field names **traffic generators and public DGA
samples**, not one downloadable benchmark that trains all six detectors. The
visible field ends mid-sentence after “Feature extraction: Extract flow”; we do
not infer requirements from its missing continuation. The table distinguishes
traffic **actually generated/captured** from offline metadata analogues and
research-only domain corpora.

| PS guidance / input | What we actually used | Purpose and exact evidence boundary |
| --- | --- | --- |
| Benign `iperf3`, Ostinato or TRex | `iperf3` 3.16 ran on WSL loopback; **Ostinato and TRex were not run**. | `scripts/generate_sih_tool_capture.sh` → local PCAP → Zeek → `examples/sih26145_tool_capture_zeek_v1.jsonl` (45 records). This proves passive ingestion, **not** benign-class accuracy. See `data/manifests/sih26145-input-compliance-v1.json`. |
| `hping3` SYN/UDP traffic | `hping3` 3.0.0-alpha-2 generated controlled SYN and UDP packets on the same loopback capture. | The same 45-record Zeek fixture verifies the packet-to-metadata-to-upload path. It is **not** a labelled, representative SYN-flood or UDP-reflection accuracy test. |
| Slowloris / slow HTTP exhaustion | `slowhttptest` 1.9.0 ran in its Slowloris/slow-header mode; the separate Slowloris executable was **not** run. | `scripts/generate_sprint34_real_tool_capture.sh` → isolated private-link PCAP → Zeek → `examples/sih26145_real_tools_v1.jsonl`; the Slow HTTP finding is measured from long-lived, low-byte connections. |
| `dnscat2` or iodine DNS tunnel | iodine 0.7.0 established a TXT-based tunnel and carried a successful ping; **dnscat2 was not run**. | The same Sprint 34 capture produced 52 native Zeek DNS transactions; the actual upload path emitted a DNS-tunnelling finding. |
| Published DGA algorithms / DGArchive | **DGArchive was not used.** The bundled `examples/dns_training_demo.csv` trains only the small deployed demonstration n-gram model. Public **UMUDGA** domains supported guarded training/validation and the failed Vawtrak holdout; **ExtraHop** tested a frozen research candidate; the [Chrmor research sample](https://github.com/chrmor/DGA_domains_dataset) supplies a pinned Kraken/Alexa campaign and domain-only control; the [Stratosphere DNS Threats Dataset](https://mcfp.felk.cvut.cz/publicDatasets/DNS-Threats-Dataset/) supplies the latest separated train/test experiment. | No research candidate replaced the demonstration model. ExtraHop reached 63.36% recall / 6.80% FPR; Chrmor reached 82% / 2%; the CTU-trained candidate reached 68.8% / 0.1% on its frozen 4,000-domain test sample and failed the unchanged 70% recall gate. The Chrmor DNS response/timing controls are simulated; CTU supplies domain labels rather than live resolver telemetry. See `docs/SPRINT_28.md`, `docs/SPRINT_30.md`, `docs/SIH_VALIDATION_FOLLOWUP.md` and `docs/SPRINT_38.md`. |
| Sandboxed C2 emulator | `scripts/lab_c2_emulator.py` generated eleven real TCP callbacks about three seconds apart inside the isolated Sprint 34 lab; it is a **timing emulator, not malware or a full C2 framework**. | Native Zeek connection records gave a periodic-beacon finding. A separate jittered, variable-size health-check capture stayed alert-free. Both enter the 141-record actual upload replay. |

Before those real-tool captures, `scripts/build_sih_lab_corpus.py` created a
**different**, deterministic 392-record offline corpus with semantic equivalents
for the PS examples. Its separate ground-truth sidecars are used only **after
inference** to score detector behaviour; that corpus is not a claim that the
named tools were executed. The 452-record mixed and 153-record identity-separated
replays are likewise controlled evaluation fixtures, not model-training data or
proof of universal accuracy. The external CTU-13 flow evaluation is an additional
independent check that exposed botnet-detection gaps, not a passing accuracy claim.
See [Sprint 20](docs/SPRINT_20.md), [Sprint 31](docs/SPRINT_31.md),
[Sprint 34](docs/SPRINT_34.md) and the [requirement audit](docs/SIH26145_REQUIREMENT_GAP_ANALYSIS.md).

The feature-extraction path is: **PCAP / collector-decoded flow export / Zeek log
→ read-only normalization → flow, DNS and TLS/QUIC metadata features → stateful
detectors → structured alerts → dashboard**. Flow features include time, endpoints,
ports, protocol, connection state, duration, bytes and packets; detectors then
derive rates, source-IP entropy, fan-out, inter-arrival variation and volume
ratios. DNS contributes query names/types/length/entropy, while encrypted-session
analysis uses available fingerprints and packet-size/timing observations without
decrypting payloads. See [ingestion and validation](docs/INGESTION_AND_VALIDATION.md)
and [models and features](docs/MODELS_AND_FEATURES.md). NetFlow/IPFIX/sFlow support
means **collector-decoded JSON/NDJSON**, not raw exporter wire decoding.

Sprint 34 adds [isolated real-tool evidence](docs/SPRINT_34.md): an actual
`slowhttptest` Slowloris-mode run, an established iodine DNS tunnel carrying ping,
eleven deterministic C2-timing callbacks and a jittered health-check control are
captured with tcpdump and converted by Zeek 8.0.10. The 141-record actual upload
replay is healthy and produces exactly Slow HTTP, C2 and DNS-tunnel findings while
the benign health source remains alert-free. Raw PCAPs remain local and gitignored.

Sprint 33 freezes the [final SIH submission release](docs/SPRINT_33.md) as
`drastha-sih-v1.0`. Its checksum-pinned manifest and executable acceptance check
cover the current HTTP upload path, both eight-behaviour replays, lab controls,
input formats, passive-safety contract, evidence persistence and demonstrated
50 records/second target. The release is submission-demo ready, not production
ready; its exclusions are explicit and machine-readable.

Sprint 32 adds the [final SIH threat and evidence validation](docs/SPRINT_32.md).
Two independent HTTP-upload replays, SQLite persistence, saved-run snapshots,
incident evidence readback, SIEM export and incremental SSE are checked together.
The 452-record result remains 8 TP / 0 FP / 0 FN / 86 TN with healthy quality;
every subtype now has a presentation-ready SIH threat class and every replay
exposes its passive/read-only safety contract.

Sprint 31 adds [SIH input-format and dataset provenance closure](docs/SPRINT_31.md).
Collector-decoded NetFlow, IPFIX and sFlow JSON/NDJSON now enter the same quality,
detection, correlation and dashboard path as Zeek records. A local-only
iperf3/hping3 PCAP was captured with tcpdump and converted by Zeek 8.0.10 into a
checksum-pinned 45-record healthy replay. Raw binary flow datagrams and broad
vendor interoperability are explicitly not claimed.

Sprint 25 adds the [checksum-pinned final SIH prototype acceptance bundle](docs/SPRINT_25.md).
One command verifies ten evidence/configuration artifacts and reruns the actual
upload replay, contextual hardening, public alert schema, deployment and
performance gates. The machine-readable result is submission-demo ready and
explicitly not production ready.

Sprint 26 adds a [deterministic prepared-host demo bundle](docs/SPRINT_26.md) with
per-file SHA-256 verification and an isolated-directory acceptance rehearsal. It
includes the compiled dashboard but deliberately excludes runtimes, dependencies,
credentials, databases and packet captures; it is not a self-contained installer.

Sprint 27 adds [safe loopback demo startup](docs/SPRINT_27.md). Port conflicts are
detected before `--fresh` can reset the demo database, an available alternative is
suggested, and the exact pre-bound listener is handed to Uvicorn. Start on another
port with `.\scripts\start-demo.ps1 -Port 8001`.

Sprint 28 adds an [independent DGA family holdout and fail-closed promotion
gate](docs/SPRINT_28.md). A predeclared n-gram/lexical hybrid passed validation but
failed final-holdout recall (34.50%, including 20.37% on Vawtrak), so promotion is
correctly rejected. Exact upload parity and healthy quality confirm a model
generalization gap, not an ingestion issue; the deployed demo model is unchanged.

Sprint 29 adds [family-blocked hashed-logistic DGA development](docs/SPRINT_29.md).
All UMUDGA families have now been inspected, so the 87,829-domain three-fold result
is deliberately non-promotable. No tested threshold satisfies the unchanged FPR,
pooled-recall and per-family gates together; a different external or future
environment dataset is required before another final promotion attempt.

Sprint 30 adds an [independent ExtraHop DGA evaluation](docs/SPRINT_30.md). The
full checksum-pinned source is streamed into a deterministic 20k benign / 20k DGA
sample after excluding UMUDGA overlaps. Direct and bounded upload-path predictions
match exactly with healthy quality, but 63.36% recall and 6.80% FPR fail the frozen
gates. Missing publisher TLD/family metadata also keeps promotion blocked.

Sprint 19 adds a real offline Zeek 8.0.10 sensor proof: a deterministic mixed
SYN/DNS/TLS PCAP produces native `conn.log`, `dns.log`, and `ssl.log`, then passes
through shared analysis and dashboard API readback with healthy quality, no
rejections, no detector network connection attempts, and no payload decryption.
See [the exact result and limitations](docs/SPRINT_19.md). This does not claim a
live mirror, QUIC interoperability, real-traffic accuracy or sustained capacity.

Sprint 20 adds a [reproducible SIH-guided offline lab corpus](docs/SPRINT_20.md):
13 isolated checksum-pinned scenarios, 392 chronological records, independent
ground-truth sidecars and an honest shared-pipeline baseline. No attack tool or
live network transmission is used.

Sprint 24 adds a [signed sustained mixed-protocol measurement](docs/SPRINT_24.md).
The shared continuous path passes every gate at 50 records/sec for 60 seconds;
two 100 records/sec attempts remain failed evidence because their maximum producer
lag exceeded 100 ms.

Sprint 23 adds a [fail-closed deployment and confidence contract](docs/SPRINT_23.md):
explicit monitored CIDRs, checksum-linked context policy, passive safety flags,
and machine-readable disclosure that detector confidence is a heuristic evidence
score rather than a calibrated attack probability.

Sprint 22 adds [contextual false-positive hardening and passive Slow HTTP
coverage](docs/SPRINT_22.md). On the 392-record SIH lab corpus, the shared path
produces 9 TP / 0 FP / 0 FN / 5 TN with checksum-pinned operator context while
preserving a counterfactual empty-context run. This is a small synthetic lab
result, not a production accuracy claim.

Sprint 21 adds a [strictly separated DGA research iteration](docs/SPRINT_21.md)
using 24 training, four validation and four previously unseen final-test families.
The frozen candidate failed validation uncertainty and final-holdout
generalization gates, so production loading remains blocked.

Latest verified baseline (10 September 2026): **454 Python tests**, **18 frontend
tests**, and a successful dashboard production build. The corrected accuracy
replay produces **8 findings, 8 incidents, 0 false-positive behaviours and healthy
input quality**. These are controlled synthetic results, not production accuracy.

The corrected 8-threat/false-positive evaluation fixture is the native replay
[`examples/drastha_accuracy_fp_test_v2.jsonl`](examples/drastha_accuracy_fp_test_v2.jsonl),
with an equivalent JSON container beside it, assumptions in the adjacent manifest,
and a reproducible upload-API check
in `scripts/check_accuracy_fixture.py`. It preserves all 53 supplied scenario
records and adds 100 prior passive TLS sessions required by the unchanged feature
extractor; do not describe its synthetic behaviour-level score as production accuracy.

Sprint 17 adds [coordinated journal/analyst backup and same-engine recovery](docs/SPRINT_17.md).
The operator tools validate a signed recovery point, reconstruct detection state
on disposable copies, and preserve the selected analyst reviews and holds.
Original source identity is required; cross-version migration and automatic
cutover remain unsupported. Follow the [recovery runbook](docs/OPERATIONS_RUNBOOK.md#8-coordinated-stream-recovery-sprint-17).

Sprint 18 adds [completed-replay SIEM export](docs/SPRINT_18.md): JSON/NDJSON
downloads with stable import identities, saved-run evidence, telemetry quality,
overall risk and signed-store receipts. In **Review full evidence**, select
**Download SIEM NDJSON**. See the documented import contract before configuring
an external importer; automated delivery and vendor-specific mappings remain open.

Sprint 16 adds [atomic continuous-ingest publication and measured optimization](docs/SPRINT_16.md)
while retaining full source and signed-evidence verification. The finite profiler
run is about 23% faster; both 1,000 records/sec experiments still fail at least one
strict load gate. Defaults and detectors are unchanged, and old checkpoints still
refuse an engine mismatch. This is not a production-capacity claim.

Sprint 15 adds [protected local startup and verified SQLite recovery](docs/SPRINT_15.md).
Use the [operator runbook](docs/OPERATIONS_RUNBOOK.md) for preflight, create-only
backup/restore and manual cutover. This is a loopback-only staged deployment path,
not a replacement for the demo Docker setup or a production-readiness certificate.

Sprint 14 adds repeatable paced-load measurements through continuous ingestion,
SQLite and the analyst API, with explicit latency/resource/failure gates, plus
an offline Zeek integration checker. These are bounded synthetic measurements,
not a production capacity guarantee; real-sensor and browser validation remain
open. See [Sprint 14 measurement contract and results](docs/SPRINT_14.md),
[Sprint 12 continuous-ingestion boundaries](docs/SPRINT_12.md) and
[Sprint 13 protected access and signed evidence](docs/SPRINT_13.md).

Sprint 11 adds a public DGA corpus, validation-only operating-point selection,
frozen holdout evaluation through upload analysis, and research-model deployment
guards. The public-data candidate **failed recall gates and was not promoted**;
the demonstration model remains unchanged. See [Sprint 11 scope, measured failures
and reproduction](docs/SPRINT_11.md). Production calibration remains unfinished.

Sprint 10 adds a checksum-pinned, split-audited independent evaluation workflow.
The external CTU-13 baseline exposed detection gaps and false positives; it does
not validate the demo's accuracy on real traffic. See [Sprint 10 results and
reproduction steps](docs/SPRINT_10.md) and the
[pinned evaluation manifest](data/manifests/ctu13_scenario11_benchmark.json).

> Drastha is a defensive research prototype. Use it only with traffic and
> systems that you are authorized to monitor. It does not automatically block
> or attack another system.

## Contents

- [SIH26145 dataset and traffic-tool provenance](#sih26145-dataset-and-traffic-tool-provenance)
- [What problem does Drastha solve?](#what-problem-does-drastha-solve)
- [What can it detect?](#what-can-it-detect)
- [How it works](#how-it-works)
- [Beginner's end-to-end walkthrough](#beginners-end-to-end-walkthrough)
- [Detection engine: what every detector sees](#detection-engine-what-every-detector-sees)
- [AI/ML model, training data and libraries](#aiml-model-training-data-and-libraries)
- [From findings to concluded incidents](#from-findings-to-concluded-incidents)
- [Data quality and false-positive control](#data-quality-and-false-positive-control)
- [Database and evidence storage](#database-and-evidence-storage)
- [Backend APIs and frontend integration](#backend-apis-and-frontend-integration)
- [Technology stack](#technology-stack)
- [Dashboard terminology](#dashboard-terminology)
- [System requirements](#system-requirements)
- [Clone and run on Windows](#clone-and-run-on-windows)
- [Clone and run on Linux](#clone-and-run-on-linux)
- [Run with Docker](#run-with-docker)
- [How to use the dashboard](#how-to-use-the-dashboard)
- [Analyse your own replay](#analyse-your-own-replay)
- [Process a PCAP with Zeek](#process-a-pcap-with-zeek)
- [Train the demonstration ML model](#train-the-demonstration-ml-model)
- [Run the tests](#run-the-tests)
- [Project structure](#project-structure)
- [Current status and limitations](#current-status-and-limitations)
- [Troubleshooting](#troubleshooting)

## What problem does Drastha solve?

Some critical networks use a network TAP or hardware data diode. Monitoring
software can observe a copy of the traffic, but it must never communicate back
to the protected network.

Drastha is designed for that situation. It works with passively collected
metadata such as:

- source and destination addresses;
- source and destination ports;
- connection time and duration;
- packet and byte counts;
- DNS queries;
- visible TLS or QUIC metadata;
- connection state.

It does not need to decrypt payloads, scan devices, inject packets, or open a
return connection to the monitored network.

## What can it detect?

| Threat behaviour | Method | Evidence shown to the analyst |
|---|---|---|
| Vertical port scan | Behavioural fan-out analysis | Unique ports, target and time window |
| Horizontal host scan | Behavioural fan-out analysis | Unique hosts, destination service and time window |
| SYN flood | Traffic-rate analysis | Attempt count, incomplete ratio and source diversity |
| Distributed-source SYN flood | Traffic-rate and normalized source-entropy analysis | Incomplete connections, source count and source-IP entropy; spoofing is not claimed |
| UDP flood | Traffic-rate analysis | Packet volume, bytes and source diversity |
| UDP reflection/amplification | Response-volume and service-pattern analysis | Direction, packet volume and response pattern |
| Slow HTTP connection exhaustion | Stateful flow-shape analysis | Long duration, partial state, low bytes/packets and estimated overlap |
| DGA-like domain/campaign | Character 3-gram Naive Bayes model plus distinct-root/NXDOMAIN campaign context | Uncalibrated model score when present, domain shape, resolver outcome, failed-query ratio and same-client fan-out |
| DNS tunnelling | Volume and entropy analysis | Query count, unique labels, length and entropy |
| C2-style callback | Statistical timing analysis | Interval consistency, size consistency and connection count |
| Encrypted-session metadata anomaly | Passive fingerprint and sequence baselines | JA3/JA4 prevalence, measured packet-size and timing anomalies |
| Possible data exfiltration | Adaptive baseline analysis | Outbound bytes, direction ratio and baseline comparison |

Drastha deliberately uses a hybrid approach. ML is used where learning character
patterns is useful. Clear statistical or behavioural methods are used where they
are easier to explain and govern.

## How it works

```text
Simulated stream, Zeek logs or PCAP
                 |
                 v
        Passive normalization
                 |
                 v
      Data quality validation
                 |
                 v
  ML + behavioural threat detection
                 |
                 v
  Label + confidence + evidence
                 |
                 v
      Incident correlation
                 |
                 v
 Transparent risk-priority scoring
                 |
                 v
 SQLite/PostgreSQL -> API -> dashboard
```

The live demonstration streams 69 simulated connection, DNS, and encrypted-
session metadata observations one at a time. It produces ten labelled findings
and eight incidents spanning every required threat family. The
highest-priority incident combines a repeated callback with abnormal outbound
transfer and receives a risk score of 100.

Risk 100 means “investigate first.” It does **not** mean 100% certainty.

Uploaded replays also receive an **overall replay risk** across their incidents:
highest incident risk + capped incident-breadth bonus + capped threat-diversity
bonus, limited to 100. The corrected accuracy fixture scores **88/100 (critical)**:
58 + 15 + 15. This policy score is an investigation priority; it does not establish
that separate incidents belong to one coordinated attack. The full calculation
is documented in [Models and features](docs/MODELS_AND_FEATURES.md#overall-replay-risk).

## Beginner's end-to-end walkthrough

This section is the shortest complete explanation of the project. Follow it from
top to bottom to understand how a file or simulated stream becomes evidence on
the dashboard.

### 1. Traffic reaches only the monitoring side

The protected network is assumed to feed a network TAP, mirror port or hardware
data diode. Drastha receives only a copied observation. It has no component that
scans an endpoint, completes a handshake, sends a packet back, blocks an address,
or decrypts TLS/QUIC payloads.

Drastha can work with five kinds of monitoring-side input:

| Input | How it enters Drastha | What it provides |
| --- | --- | --- |
| JSONL/NDJSON or JSON replay | Browser upload or CLI | Connection, DNS and TLS/QUIC metadata records |
| Zeek logs | Zeek adapters | `conn.log`, `dns.log`, `ssl.log` and QUIC-style metadata |
| NetFlow/IPFIX/sFlow-like JSON | Flow-export adapter | Canonical endpoints, ports, protocol, counters and timestamps |
| Classic PCAP | Local PCAP reader or Zeek runner | Packet-header-derived flow and encrypted-session metadata; payload decryption is never performed |
| Simulated stream | `GET /api/stream/simulated` | One observation at a time through the same analysis session used by replay processing |

The browser upload accepts `.jsonl`, `.ndjson` and `.json`, up to 5 MB and
20,000 records. Supported JSON containers are:

- one JSON object per line;
- one JSON array of record objects;
- one traffic-record object;
- a wrapper shaped as `{"records": [...]}`.

A dataset manifest that merely says `"records": 452` is not traffic and is
rejected with a message asking for the referenced JSONL file.

### 2. Records are parsed and normalized

`ingestion/replay_input.py` identifies the JSON container and preserves original
line numbers. `ingestion/passive_replay.py` then detects each record family and
normalizes aliases into one of three typed contracts:

| Internal contract | Important fields | Used by |
| --- | --- | --- |
| `NetworkEvent` | timestamp, flow ID, source/destination IP and port, protocol, duration, byte/packet counters, connection state | Recon, DDoS, C2 and exfiltration detectors |
| `DNSEvent` | timestamp, flow ID, client/resolver IP, query, record type, response code, answers | DGA and DNS-tunnelling detectors |
| `EncryptedSessionMetadata` | timestamp, flow ID, endpoints, TLS/QUIC transport, SNI, version, cipher, ALPN, JA3/JA3S/JA4-style fingerprints | Encrypted-session anomaly detector and C2 enrichment |

Common Zeek-native connection fields are `ts`, `uid`, `id.orig_h`,
`id.resp_h` and `proto`; ports and flow statistics provide the features required
by particular detectors. The normalizer also accepts documented aliases such as
`timestamp`, `flow_id`, `src_ip` and `dst_ip`. Conflicting aliases are rejected
instead of silently choosing one.

Uploaded fields such as `evaluation_label`, `ml_label`, `approved_backup`,
`scheduled_health_check` or a supplied attack name are never trusted as detector
input. Evaluation labels are retained only for optional post-inference scoring.

### 3. Quality is checked before detector ordering

The quality monitor examines records in their original input order. It counts:

- accepted, rejected and quarantined records;
- invalid JSON, timestamps, addresses, ports and protocols;
- timestamps that move backwards and their maximum backward skew;
- exact and conflicting duplicate flow identifiers;
- detected schemas, aliases and feature coverage.

After that check, accepted events are ordered by event time for deterministic
detector processing. Sorting never erases the original out-of-order quality flag.
Quality is:

- `healthy` when accepted input has no ordering, duplicate or rejection issue;
- `degraded` when usable input contains any such issue;
- `unusable` when no supported observation remains or more than 10% is rejected.

### 4. One isolated analysis session processes the stream

Every upload or simulated stream gets a new `AnalysisSession`; detector windows
and cooldowns are not shared between unrelated runs. At each timestamp the
session routes the typed event to the applicable detectors. TLS/QUIC metadata at
the same timestamp is ordered before the related connection so that only already
observed metadata can enrich the flow. No future look-ahead is used.

Connection records are sent to reconnaissance, DDoS, C2 and exfiltration
detectors. DNS records go only to DNS analytics. TLS/QUIC metadata goes to the
encrypted-session detector and can enrich later C2 evidence. When configured,
internal CIDRs determine inbound/outbound direction before exfiltration analysis.

### 5. Stateful detectors maintain bounded windows

The detectors process records incrementally. A keyed sliding window keeps only
the recent observations needed for the relevant source, destination or service.
An alert is produced as soon as a threshold is crossed. Cooldowns stop every
subsequent packet or flow from creating another identical alert.

At completed-replay time, final reconnaissance snapshots may enrich the evidence,
but they never replace a threshold-crossing alert that happened earlier. This is
why a scan cannot disappear merely because it is outside the final ten-second
window.

### 6. Findings are resolved and deduplicated

`findings.py` applies two important conflict rules:

1. If the same flows form a reconnaissance fan-out, a generic SYN-flood finding
   on those flows is suppressed. This prevents a port scan from simultaneously
   appearing as DDoS.
2. Repeated findings with the same threat type, subtype, source and destination
   are merged. Their time range and flow IDs are combined and the strongest
   confidence is retained.

The resulting record is a standardized `drastha-alert-v1` alert with timestamp,
flow identifier, threat class, confidence, severity and supporting evidence.

### 7. Related alerts become incidents

`IncidentStore` correlates alerts from the same source when their observation
windows are within 900 seconds. An incident can therefore combine, for example,
a periodic callback and an outbound-volume anomaly without merging unrelated
sources.

For every incident Drastha calculates risk, builds an evidence-backed conclusion,
and records a likely objective, attack stage, potential impact and uncertainty.
These are cautious hypotheses derived from passive measurements—not claims that
the attacker's identity or intent has been proven.

### 8. Results are persisted and returned

Alerts, incidents and the complete run snapshot are written through the repository
layer. The analysis response contains quality, schema, feature coverage, policy
suppression counts, alerts, incidents, overall risk, stage timings and explicit
passive-safety flags. A unique `run_id` keeps each replay's full evidence separate
even if two runs reuse the same IPs or flow IDs.

### 9. The React dashboard renders the response

The frontend posts the selected file to `POST /api/replays/analyse`. It then shows
the result returned for that exact run, refreshes the saved incident queue through
`GET /api/incidents`, and opens complete evidence through either the run snapshot
or `GET /api/incidents/{incident_id}`. It does not reuse a previous run's highest-
risk incident as the evidence for a new file.

For the simulated stream, the browser opens a server-sent-events connection to
`GET /api/stream/simulated`. `started`, `traffic`, `alert` and `complete` messages
update the progress bar, network animation, findings and final incident risk as
records arrive.

## Detection engine: what every detector sees

The following are code defaults unless a named demo profile is noted. They are
transparent prototype operating points, not universal production thresholds.

| Detector and final class | Input and grouping | Main decision evidence | Important default operating point |
| --- | --- | --- | --- |
| Vertical port scan | Connection events grouped by source, then destination host | Distinct destination ports and attempts inside the window | 20 ports in 10 s; browser upload demo uses 5 |
| Horizontal host scan | Connection events grouped by source and destination service | Distinct destination hosts on the same port | 20 hosts in 10 s; browser upload demo uses 5 |
| Multi-host/port scan | One source across several hosts and ports | Overall port fan-out without one host meeting vertical-scan shape | 20 ports and at least 2 hosts; upload demo uses 5 ports |
| SYN flood | TCP flows grouped by target | Flow count, `S0`/`REJ` incomplete ratio and target-port concentration | 100 attempts in 5 s, at least 80% incomplete and 80% concentrated on one target port; demo uses 5 attempts |
| Distributed-source SYN flood | Same SYN-flood window | Distinct sources plus normalized source-IP entropy | At least 3 sources and entropy at least 0.85; source diversity does not prove spoofing |
| UDP flood | UDP flows grouped by target | Aggregate packet volume and target concentration | 1,000 packets in 5 s; demo uses 500 |
| UDP reflection/amplification | UDP service flows | At least 4 flows, responder/request byte ratio and responder volume | Ratio at least 10:1 and at least 10,000 response bytes; deployment profile also requires reflection-service context |
| Slow HTTP exhaustion | TCP flows to an HTTP-labelled target | Long-lived partial connections, small transfers, small packet counts and estimated overlap | 20 candidate connections in 15 s; each at least 120 s, at most 2,048 bytes and 16 packets |
| Botnet C2 beaconing | Completed non-DNS flows grouped by source, destination, port and protocol | Repeated callbacks, mean interval, interval coefficient of variation, size variation, observation span and completion ratio | At least 6 connections; mean interval 2–120 s; interval CV ≤0.15; size CV ≤0.20; span ≥30 s; mean transfer ≤2,048 bytes; completion ≥80% |
| DGA domain activity | DNS query plus same-client campaign context | 3-gram model score, lexical shape, distinct roots and actual resolver results | Demo model score threshold 0.50; known response status requires multiple model-positive roots; failed campaign requires 12 queries, 10 roots and at least 80% NXDOMAIN in 60 s |
| DNS tunnelling | DNS queries grouped by client and base domain | Query count, unique subdomain labels, average length, Shannon entropy and TXT ratio | 20 queries, 15 unique labels and length ≥18 or entropy ≥3.5; encoded-TXT path needs 4 queries, ≥75% TXT, length ≥24 and entropy ≥3.5 |
| Encrypted-session metadata anomaly | TLS/QUIC sessions grouped by source, destination and client fingerprint | Repetition, fingerprint prevalence, packet-size-sequence anomaly and timing-sequence anomaly | 4 sessions in 60 s, prevalence ≤1%, size anomaly ≥0.75 and timing anomaly ≥0.75 |
| Outbound-volume anomaly | Direction-normalized flows grouped by source/destination with a per-source history | Outbound volume, outbound/inbound ratio and median-baseline multiplier | Stateful path: 3 flows in 300 s, ≥1 MB, ≥8:1 and ≥4× baseline; extreme path: ≥10 MB and ≥20:1 |

All detectors emit the measurements that caused the decision. For example, the
C2 detector does not alert merely because port 443 or a rare fingerprint exists;
timing, size, span and completion conditions must agree. Similarly, encrypted-
session rarity alone cannot produce a malware claim.

## AI/ML model, training data and libraries

### What is actually model-based?

The only deployed supervised ML classifier is the DGA domain classifier. DDoS,
reconnaissance, C2, DNS tunnelling, encrypted-session anomaly and exfiltration
are explainable stateful/statistical detectors. This is intentional: flow-rate,
fan-out, periodicity and byte asymmetry have direct measurable definitions and do
not require pretending that one opaque model can understand every attack.

### Deployed DGA algorithm

The deployed demonstration artifact is a custom **Multinomial Naive Bayes**
classifier over boundary-aware normalized domain character **3-grams**:

1. Normalize the domain.
2. Split it into overlapping three-character tokens.
3. Count token frequency in benign and DGA training classes.
4. Apply Laplace smoothing to class/token likelihoods.
5. Combine the prior and token log-likelihoods.
6. Convert the two class scores into a bounded model score.
7. Compare that score with the model operating threshold.

The implementation is pure Python in `src/aegisflow/dns_model.py`; it does not
use scikit-learn, TensorFlow or PyTorch. This keeps the model JSON inspectable and
the inference path dependency-light. The score is **not** a calibrated infection
probability.

Lexical features used by research candidates and campaign context include domain
length, Shannon entropy, digit ratio, vowel ratio, label count, maximum label
length, hyphen ratio and unique-character ratio. A bounded signed-hash logistic
regression implementation also exists for research, but failed candidates cannot
be loaded by the normal deployment model loader.

### Dataset usage and honest result boundary

| Dataset or source | How it was used | Deployment status |
| --- | --- | --- |
| `examples/dns_training_demo.csv` | Small train/test demonstration of normalization, 3-gram Naive Bayes fitting, inference, metrics and model-card generation | Produces the bundled demo model; not a production-accuracy claim |
| UMUDGA | Family-separated research training, validation and holdouts for n-gram/lexical and hashed-logistic candidates | Candidates failed frozen generalization gates; not deployed |
| ExtraHop DGA Detection Training Dataset | Independent 40,000-domain evaluation of a frozen candidate | 63.36% recall / 6.80% FPR; failed |
| Chrmor DGA/Alexa sample | Frozen Kraken/Alexa domain test and simulated resolver-campaign controls | Domain-only candidate reached 82% recall / 2% FPR; failed the 1% FPR gate |
| Stratosphere DNS Threats Dataset | Official training split for the latest candidate and a prediction-blind 2,000 DGA + 2,000 benign upload-path holdout | 68.8% recall / 0.1% FPR; failed the unchanged 70% recall gate by 1.2 points; not deployed |
| `iperf3`, `hping3`, `slowhttptest`, iodine and the C2 timing emulator | Lab traffic generation and PCAP/Zeek integration evidence for behavioural detectors | Test evidence only; these tools do not train the DGA model |

Training uses deterministic splits, duplicate and family-leakage guards,
validation-only threshold selection, checksum-pinned manifests, confusion counts,
precision/recall/F1/FPR and create-only artifacts. A research artifact is promoted
only if its frozen gates pass. Failed candidates remain marked
`research_status: not_approved` and cannot silently replace the bundled model.

Detailed experiments and limitations are recorded in
[Models and features](docs/MODELS_AND_FEATURES.md), [Sprint 28](docs/SPRINT_28.md),
[Sprint 30](docs/SPRINT_30.md) and [Sprint 38](docs/SPRINT_38.md).

## From findings to concluded incidents

### Standard alert schema

Every finding is converted to the same public shape regardless of detector:

```json
{
  "schema_version": "drastha-alert-v1",
  "timestamp": 1790000123.4,
  "flow_identifier": "C8abc123",
  "threat_class": "Botnet C2 Beaconing",
  "confidence": 0.87,
  "confidence_is_probability": false,
  "severity": "high",
  "src_ip": "10.0.0.15",
  "dst_ip": "198.51.100.20",
  "supporting_evidence": [
    {
      "name": "mean_interval_seconds",
      "observed": 3.0,
      "comparison": "between 2.0 and 120.0",
      "explanation": "The average delay is consistent with periodic callback behaviour."
    }
  ]
}
```

`confidence` is a deterministic evidence-strength score inside the detector. It
helps rank two findings from the same logic, but it is not “87% probability that
the host is infected.” Each alert also carries detector/version provenance,
observation window, related flow IDs, all evidence and scientific limitations.

### Incident correlation and score

Alerts are grouped by source and overlapping/nearby time within 900 seconds.
The incident risk formula is transparent:

```text
incident risk = distinct threat-category weights
              + 8 × additional independent detectors
              + round(average alert confidence × 20)
              capped at 100
```

Threat weights are reconnaissance 15, denial of service 25, DNS threat 25,
command and control 35, and data exfiltration 40. Severity is low below 35,
medium from 35, high from 60, and critical from 80.

The replay-wide risk uses the highest incident risk as its base, then adds up to
15 points for incident breadth and up to 15 for threat-category diversity. It is
an investigation-priority score, not attack probability and not proof that all
incidents belong to one campaign.

### Why “Review incident” is a conclusion, not duplicate text

`build_incident_conclusion` maps the actual alert subtypes to cautious security
objectives. It records:

- `assessment`: what behaviour was observed and where;
- `likely_objective`: the plausible purpose, such as discovery, availability
  disruption, command-and-control contact or data movement;
- `attack_stage`: the inferred stage supported by the findings;
- `potential_impact`: what could happen if the hypothesis is correct;
- `confidence_basis`: up to four concrete evidence statements;
- `uncertainty`: detector limitations and the fact that passive metadata cannot
  prove operator identity or intent.

The conclusion is created from detector alerts only, never from evaluation labels.

## Data quality and false-positive control

Drastha reduces false alerts at several independent layers:

- **Threat-specific features:** scans use fan-out, floods require target
  concentration, C2 requires periodic low-variation callbacks, DNS tunnelling
  uses DNS fields, encrypted anomalies require fingerprint plus two independent
  sequence anomalies, and exfiltration requires directional volume asymmetry.
- **Conflict resolution:** reconnaissance evidence suppresses an overlapping
  generic SYN-flood interpretation.
- **Exact context policy:** trusted monitoring endpoints, approved bulk-transfer
  endpoints and authorized scanner sources can suppress only an exact operator-
  owned rule. Replay-provided “approved” labels are ignored.
- **Allow-lists and service routing:** DNS traffic is not evaluated as C2; known
  domain/destination rules are applied from monitoring-side configuration.
- **Multiple-signal gates:** rare JA3/JA4, HTTPS use, high entropy, one large
  connection or one failed DNS query is not enough by itself.
- **Baselines and cooldowns:** source history distinguishes normal transfer size;
  cooldowns and deduplication prevent repeated copies of the same finding.
- **Four separate dashboard outcomes:** detected threat, approved context,
  insufficient evidence and invalid/rejected input are never treated as the same
  state.

`config/context_policy.json` is a demo policy and must be replaced and change-
controlled for a real environment. A broad allow rule can hide malicious traffic.

## Database and evidence storage

### Local SQLite mode

By default the API stores data in `output/drastha.db` using Python's built-in
`sqlite3`. Set `DRASTHA_DB` to another local path. Each write uses a transaction;
errors roll back and connections close immediately.

| Table | Purpose |
| --- | --- |
| `incidents` | Current prioritized incident projection, risk, status and complete JSON payload |
| `alerts` | Standardized alert payloads linked to incidents |
| `analyst_feedback` | Analyst disposition, identity, timestamp and notes |
| `analysis_runs` | Complete run-scoped report used by full-evidence review and SIEM export |
| `runtime_state` | Checkpointable state for bounded continuous ingestion/recovery |

Incident and alert imports are idempotent upserts. Reprocessing detector evidence
does not reset analyst-owned status or feedback. Run snapshots are separate from
the global queue so the evidence for one upload cannot leak into another.

### PostgreSQL and protected mode

Docker deployment includes the equivalent PostgreSQL schema under
`deploy/postgres/`. The repository is selected from `DRASTHA_DB`. Optional
protected mode adds access control, HMAC-verified evidence operations, retention
preview/apply APIs and legal holds. The ordinary local demo is intentionally
reported as `unsigned-demo`; it must not be described as externally anchored
forensic custody.

## Backend APIs and frontend integration

The backend is FastAPI. The built React application is served by the same service,
so browser requests normally use relative `/api/...` URLs.

```text
Browser file
   |
   | POST /api/replays/analyse  { filename, content }
   v
FastAPI -> parser -> quality -> AnalysisSession -> findings -> incidents
   |                                                   |
   +---------------- SQLite/PostgreSQL <---------------+
   |
   +--> JSON run result -> React replay result and full-evidence view
   +--> GET /api/incidents -> saved SOC investigation queue
   +--> GET /api/incidents/{id} -> alerts + conclusion + feedback
```

| Method and endpoint | Role in the system | Main consumer |
| --- | --- | --- |
| `GET /api/health` | Service mode, storage type, access mode and last demo state | Header/system status |
| `GET /api/metrics` | Active/critical counts, review count and average risk | SOC overview cards |
| `POST /api/replays/analyse` | Validate and analyse a finite uploaded replay | Replay workbench |
| `GET /api/replays/sample` | Download a safe example replay | Beginner/demo flow |
| `GET /api/stream/simulated` | Server-sent events for incremental passive simulation | Live visualization |
| `POST /api/demo/run` | Execute the known instant replay story | Demo button |
| `POST /api/demo/load` | Load saved demonstration evidence | Offline rehearsal tooling |
| `GET /api/incidents` | Risk-ordered queue with optional status/severity filters | Investigation queue |
| `GET /api/incidents/{id}` | Complete incident, member alerts, conclusion and feedback | Incident review drawer |
| `PATCH /api/incidents/{id}/status` | Set open, investigating, resolved or false-positive status | Analyst workflow |
| `POST /api/incidents/{id}/feedback` | Record confirmed-malicious, benign or needs-review disposition | Analyst workflow |
| `GET /api/incidents/{id}/export` | Export one incident with optional integrity metadata | Evidence handoff |
| `GET /api/analysis-runs/{run_id}` | Retrieve the exact saved replay result | Run-scoped evidence |
| `GET /api/analysis-runs/{run_id}/export` | Export validated JSON/NDJSON SIEM records | SIEM handoff |
| `/api/security/*` | Verify signed evidence, preview/apply retention and set holds | Protected administrator mode |

The upload body is validated by Pydantic, domain errors become clear HTTP 422
responses, missing evidence returns 404, and integrity failures fail closed with
HTTP 503. FastAPI exposes interactive OpenAPI documentation at `/docs` when the
dashboard catch-all is not occupying that route in a custom setup.

## Technology stack

| Layer | Technology/library | Why it is used |
| --- | --- | --- |
| Detection core | Python 3.11+, standard library | Typed events, sliding windows, statistics, custom ML and deterministic scoring without a heavy runtime |
| API and validation | FastAPI, Pydantic, Uvicorn | REST/SSE endpoints, request validation and local server |
| Local database | SQLite through `sqlite3` | Dependency-free transactional demo storage |
| Team/container database | PostgreSQL through Psycopg | Durable Docker deployment with equivalent logical schema |
| Network metadata | Zeek 8.x integration and internal PCAP header parser | Passive connection/DNS/TLS metadata extraction |
| Frontend | React, TypeScript, Vite, Lucide React | Typed SOC dashboard, build tooling and icons |
| Tests | Python `unittest`, Node's built-in test runner | Backend, detector, ingestion, evidence and frontend regression tests |
| Packaging/deployment | setuptools, Docker and Docker Compose | Installable `drastha` CLI and reproducible local/container launch |

The Python project's core dependency list is intentionally empty. API/PostgreSQL
packages are optional dependencies under the `api` extra.

## Dashboard terminology

| Dashboard term | Exact meaning |
| --- | --- |
| Record | One accepted passive connection, DNS or encrypted-session observation |
| Finding / alert | One deduplicated behaviour that crossed a detector threshold |
| Incident | One or more time-related alerts correlated around the same source |
| Threat class | Human-readable standardized label such as `Volumetric DDoS - SYN Flood` |
| Confidence | Detector-specific evidence strength from 0 to 1; not probability |
| Risk | Transparent incident/replay investigation priority from 0 to 100 |
| Severity | Policy band derived from evidence/risk: low, medium, high or critical |
| Evidence | Observed value, comparison/threshold and plain-English explanation |
| Conclusion | Evidence-backed likely objective, stage, potential impact and uncertainty |
| Data quality | Whether the input was structurally valid, ordered and non-duplicated |
| Feature coverage | Which connection, DNS, encrypted and derived measurements were actually available |
| Approved context | Exact monitoring-side policy match that suppressed evaluation |
| Insufficient evidence | A detector could not yet score the record; this is not a benign verdict |
| TP / FP / FN / TN | Evaluation-only comparison against supplied scenario labels, never detector input |
| Precision / recall / F1 / FPR | Behaviour-level fixture metrics; not automatically real-world accuracy |

## System requirements

### Required for the easiest local demo

| Requirement | Minimum | Why it is needed |
|---|---:|---|
| Git | Recent version | Clone the repository |
| Python | 3.11 or newer | Detection pipeline and API |
| Node.js | 20 or newer | Build the dashboard |
| pnpm or Corepack | Recent version | Install dashboard packages |
| Browser | Current Chrome, Edge or Firefox | Open the dashboard |
| Free disk space | About 2 GB recommended | Dependencies, build files and local database |
| Memory | 4 GB recommended | Comfortable local demonstration |

A GPU is **not required**.

Internet access is required only for the first dependency installation. The
normal SQLite demonstration works offline after setup.

### Windows requirements

- Windows 10 or Windows 11;
- PowerShell 5.1 or newer;
- Python added to `PATH`;
- Node.js with Corepack or pnpm.

WSL is optional. It is needed only when you want to process raw PCAP files with
Zeek on Windows.

### Linux requirements

- A recent Linux distribution;
- Python 3.11 or newer with `venv` support;
- Node.js 20 or newer;
- pnpm or Corepack.

Zeek and Docker are optional.

### Optional production-style tools

- Docker Engine or Docker Desktop with Compose v2;
- PostgreSQL 16 through the included Docker configuration;
- Zeek 8 or a compatible recent release for raw PCAP conversion;
- WSL2 with Ubuntu when using Zeek from Windows.

## Clone and run on Windows

### 1. Clone the repository

```powershell
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha
```

### 2. Run the one-time setup

Keep the internet connected for this step:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

The setup script:

1. creates `.venv`;
2. installs the Python API and detector dependencies;
3. installs and builds the React dashboard;
4. rehearses the complete demo twice.

### 3. Start Drastha

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-demo.ps1
```

Keep the PowerShell window open. The dashboard should open automatically at:

```text
http://127.0.0.1:8000
```

You can also right-click `scripts/start-demo.ps1` and choose **Run with
PowerShell**.

## Clone and run on Linux

The Windows scripts are the most thoroughly tested setup path. On Linux, run
the equivalent commands manually:

```bash
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[api]"

cd web
corepack enable
pnpm install --frozen-lockfile
pnpm run build
cd ..

export PYTHONPATH="$PWD/src"
python -m aegisflow.cli demo-rehearse --evaluation-iterations 50
python -m aegisflow.cli demo-serve --fresh
```

Then open `http://127.0.0.1:8000`.

If `corepack` is unavailable, install pnpm using the official pnpm
installation instructions and repeat the dashboard commands.

## Run with Docker

Docker runs the dashboard and API with PostgreSQL. It is optional for the SIH
demo.

```powershell
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha
docker compose up --build
```

Open `http://127.0.0.1:8000`.

Stop the containers with:

```powershell
docker compose down
```

The PostgreSQL data is stored in the `drastha-data` Docker volume. The password
in `docker-compose.yml` is for the local demonstration only and must be replaced
before any shared deployment.

## How to use the dashboard

### Live one-way stream demonstration

1. Open the dashboard.
2. Confirm **Sensor online**, **SQLite storage**, and **One-way monitoring**.
3. Click **Start live IP simulation**.
4. Watch records arrive one at a time.
5. Observe the alerts appear while the stream is still running.
6. Confirm the final result:

   - 67 records analysed;
   - 10 labelled alerts;
   - 8 incidents;
   - highest risk score 100.

The findings demonstrate:

- real inference from the trained DGA ML model;
- DNS tunnelling analysis;
- repeated C2-style callback detection;
- abnormal outbound-transfer detection;
- vertical port scanning without a duplicate DDoS classification;
- SYN, distributed-source SYN, UDP-flood, and reflection/amplification paths;
- encrypted-session anomaly detection from TLS/JA4, size, and timing metadata.

Click **Open scored intelligence** to see a recorded incident conclusion: the
observed behaviour, likely objective, attack stage, potential impact, evidence
basis and analytical uncertainty. The same view then separates the detection
timeline, raw supporting measurements and priority-score calculation. Because
Drastha is passive, it reports intent as an evidence-backed hypothesis rather
than a proven fact.

### Instant attack replay

Use **Run instant replay** when you need a shorter demonstration. It runs the C2
and exfiltration attack story immediately and stores one correlated incident.

### Analyst workflow

Open an incident to:

- change the status;
- record a malicious, benign or needs-review decision;
- add investigation notes;
- review the recorded likely objective and its uncertainty;
- inspect every contributing alert;
- export the complete incident as JSON.

## Analyse your own replay

The dashboard accepts safe Zeek connection records and can route embedded DNS
and TLS/JA3/JA4 metadata to their threat-specific detectors. Supported JSON
shapes are:

- `.jsonl`;
- `.ndjson`;
- a `.json` array.
- a `.json` object containing a `records` array.

Both native Zeek Unix timestamps and ISO-8601 timestamps are accepted. Supplied
ground-truth fields such as `label`, `threat_class`, `confidence`, and expected
`evidence` are never trusted as predictions; Drastha calculates its own labels,
confidence and evidence from the telemetry features.

Maximum upload size: 5 MB.

Use **Download a sample attack replay** if you want a known-good example. Drag
the file into **Analyse your own replay** or choose it using the file picker.

The uploaded content is:

1. validated;
2. normalized;
3. analysed by the configured detectors;
4. correlated and scored;
5. displayed as plain-language intelligence.

The original uploaded file is not retained by the local application.

Completed analysis snapshots, findings, incidents and supporting evidence are
stored in the configured analyst database (`output/drastha.db` by default for
SQLite). **Review full evidence** and **Review this incident** use the selected
replay snapshot, so evidence from another upload is not substituted. Exports
include the recorded conclusion, likely objective and uncertainty.

### Reproduce the eight-threat accuracy test

Upload **`examples/drastha_accuracy_fp_test_v2.jsonl`**. This is different from the
original `drastha_accuracy_fp_test.jsonl` draft, whose invalid timestamps and
incomplete DNS/TLS evidence can produce only five incidents. The corrected fixture
preserves 53 scenario records and adds 100 passive TLS baseline observations.

```powershell
.\.venv\Scripts\python.exe scripts/check_accuracy_fixture.py --fixture examples/drastha_accuracy_fp_test_v2.jsonl --report-output output/accuracy-check-new.json
```

Choose a new report filename each time. This check calls the actual upload API in
a temporary database and verifies saved-run readback.

| Measurement | Corrected fixture |
|---|---:|
| Received / accepted / rejected | 153 / 153 / 0 |
| Findings / incidents | 8 / 8 |
| Behaviour-level TP / FP / FN / TN | 8 / 0 / 0 / 107 |
| Precision / recall / F1 | 100% / 100% / 100% |
| Timestamp regressions / duplicate UIDs | 0 / 0 |
| Data quality | healthy |
| Overall investigation priority | 88/100, critical |

Health checks, approved backups and authorized scanners remain benign under the
operator-owned context policy. The 100 baseline encrypted sessions have
insufficient evidence while warming up; four suspicious sessions receive measured
features. The dashboard displays detected, context-suppressed, insufficient and
rejected outcomes separately.

Raw PCAP files are not accepted directly by the browser. Convert them through
Zeek using the command-line path below.

## Process a PCAP with Zeek

### Check whether Zeek is available

Activate the virtual environment first, then run:

```powershell
$env:PYTHONPATH = "src"
drastha check-zeek
```

### Windows

Install WSL2, Ubuntu and Zeek inside the Linux environment. Drastha's automatic
mode will use the WSL Zeek executable when it is available.

The verified Sprint 19 setup uses Ubuntu 24.04 WSL and Zeek 8.0.10 at
`/opt/zeek/bin/zeek`. Before analysing an operator capture, reproduce the
create-only offline sensor check with a new report filename:

```powershell
.venv\Scripts\python.exe scripts\check_sensor_integration.py `
  --mode wsl --distribution Ubuntu-24.04 `
  --report-output output\sensor-check.json
```

```powershell
$env:PYTHONPATH = "src"
drastha pcap `
  --input path\to\capture.pcap `
  --zeek-output output\zeek `
  --output output\pcap_alerts.jsonl `
  --health-output output\pcap_health.json
```

### Linux

Install Zeek and ensure the `zeek` command is available on `PATH`, then run:

```bash
export PYTHONPATH="$PWD/src"
drastha pcap \
  --input path/to/capture.pcap \
  --zeek-output output/zeek \
  --output output/pcap_alerts.jsonl \
  --health-output output/pcap_health.json
```

Only process captures that you are authorized to inspect. Raw `.pcap` and
`.pcapng` files are ignored by Git so they are not accidentally committed.
The Zeek output directory must be new or empty; Drastha refuses to overwrite or
mix existing evidence.

## Train the demonstration ML model

The repository includes a versioned demonstration model so a fresh clone works
immediately. To retrain it from the bundled dataset:

### Windows PowerShell

```powershell
$env:PYTHONPATH = "src"
drastha train-dns `
  --dataset examples/dns_training_demo.csv `
  --model-output output/models/dns_dga_demo.json `
  --metrics-output output/dns_model_metrics.json `
  --model-card-output output/DNS_MODEL_CARD.md
```

### Linux

```bash
export PYTHONPATH="$PWD/src"
drastha train-dns \
  --dataset examples/dns_training_demo.csv \
  --model-output output/models/dns_dga_demo.json \
  --metrics-output output/dns_model_metrics.json \
  --model-card-output output/DNS_MODEL_CARD.md
```

The bundled dataset is intentionally small. Its results prove that training,
inference, leakage checks, metrics and model-card generation work. They are not
a production accuracy claim.

## Run the tests

### Windows

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Linux

```bash
source .venv/bin/activate
python -m unittest discover -s tests -v
```

The verified baseline contains 390 Python tests covering ingestion,
detectors, ML training, correlation, persistence, API workflows, replay upload,
near-real-time streaming, telemetry quality, PCAP integration and restart
behaviour.

Frontend regression tests and build:

```powershell
cd web
node --test tests/*.test.mjs
pnpm run build
cd ..
```

The canonical mixed evaluation replay is
`examples/drastha_mixed_evaluation_v3.jsonl`. Its 452 labelled records are in
strict timestamp order so the unchanged input-quality monitor reports healthy
telemetry while the upload path detects all eight intended behaviours.

Validate a replay without importing incidents:

```powershell
python -m aegisflow.validate_replay examples/drastha_mixed_evaluation_v3.jsonl
```

Build the dashboard separately with:

```bash
cd web
pnpm run build
```

## Useful verification commands

Run the pre-presentation check:

```powershell
$env:PYTHONPATH = "src"
drastha demo-preflight --report-output output/drastha_demo_preflight.json
```

Run every controlled threat scenario and generate a report:

```powershell
$env:PYTHONPATH = "src"
drastha evaluate-demo --iterations 250 `
  --report-output output/drastha_evaluation_report.json
```

Rehearse the complete demo twice and check duplicate protection:

```powershell
$env:PYTHONPATH = "src"
drastha demo-rehearse --evaluation-iterations 50
```

## Project structure

```text
Drastha/
├── src/aegisflow/          Python ingestion, detectors, ML, API and storage
│   ├── detectors/          Recon, DDoS, DNS, C2 and exfiltration detectors
│   └── ingestion/          Zeek connection, DNS, TLS/QUIC and PCAP adapters
├── web/                    React and TypeScript dashboard
├── examples/               Safe, versioned demonstration traffic
├── tests/                  Automated test suite
├── output/                 Model, reports and demonstration evidence
├── deploy/postgres/        PostgreSQL schema
├── scripts/                Windows setup and start scripts
├── docs/                   Architecture, status, sprints and demo guides
├── Dockerfile              Container image definition
├── docker-compose.yml      API, dashboard and PostgreSQL deployment
└── pyproject.toml          Python package and dependency definition
```

The installed product command is named `drastha`. The internal Python package is
still called `aegisflow` for compatibility with earlier development history.

## API endpoints

The FastAPI service exposes endpoints under `/api`, including:

- `/api/health` — service and storage health;
- `/api/incidents` — prioritized incident queue;
- `/api/incidents/{id}` — complete evidence and timeline;
- `/api/replays/analyse` — analyse a browser-uploaded replay;
- `/api/analysis-runs/{run_id}` — saved replay report;
- `/api/analysis-runs/{run_id}/export?format=ndjson` — completed-run SIEM export (JSON also supported);
- `/api/stream/simulated` — monitoring-side near-real-time demonstration feed;
- `/api/metrics` — incident summary metrics.

FastAPI's generated API documentation is available at `/docs` when the static
dashboard catch-all is not taking precedence in a custom development setup.

## Passive-safety properties

- No network-scanning function exists in the pipeline.
- No detector sends packets to a monitored source or destination.
- TLS and QUIC payloads are not decrypted.
- Fingerprints can support context but cannot trigger a C2 alert alone.
- Automatic blocking is intentionally outside the passive monitoring boundary.
- Bad or excessively damaged telemetry is reported instead of silently accepted.

## Current status and limitations

### Completed for the SIH demonstration

- passive simulated streaming;
- Zeek JSONL ingestion and normalization;
- raw PCAP-to-Zeek adapter;
- ML, behavioural and statistical detection paths;
- evidence-rich labelled alerts;
- confidence, severity and transparent risk scoring;
- cross-detector correlation;
- SQLite and PostgreSQL persistence;
- responsive analyst dashboard;
- analyst review and evidence export;
- Docker deployment;
- offline setup, preflight and recovery workflow.

### Still required for production

- real-sensor validation and seamless log rotation beyond the bounded file follower;
- representative licensed datasets and environment-specific calibration;
- independently measured false-positive and false-negative rates per threat family;
- state compaction, multi-sensor ordering and cross-version checkpoint migration;
- passing sustained 1,000-records/sec gates and longer all-protocol load tests;
- SSO/MFA and credential lifecycle beyond existing opt-in role-based access;
- encrypted/offsite storage, key rotation and external audit-head custody;
- service supervision, high availability and upgrades beyond same-engine recovery;
- SIEM/SOAR integration and operational governance.

Signed 100-records/sec runs passed. Recent 1,000-records/sec, batch-256 runs
processed 60,000 records with healthy quality but still failed the unchanged
100 ms producer-scheduling gate. The higher target remains unproven.

See
[`docs/PRODUCTION_LIMITATIONS.md`](docs/PRODUCTION_LIMITATIONS.md) for the full
backlog and [`docs/STATUS.md`](docs/STATUS.md) for verified progress.

## Troubleshooting

### Python is not found

Install Python 3.11 or newer and enable **Add Python to PATH**, then open a new
terminal.

### PowerShell blocks the script

Run it using the explicit bypass command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

### pnpm is not found

Install a current Node.js release, then run:

```powershell
corepack enable
```

Run the setup script again afterward.

### Port 8000 is already in use

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m aegisflow.cli demo-serve --fresh --port 8001
```

Then open `http://127.0.0.1:8001`.

### Docker is unavailable

Use the normal SQLite setup. Docker is not required for the dashboard, live
simulation, upload analysis, evidence review or export.

### Zeek or WSL is unavailable

Use the included Zeek-style demonstration files. Zeek is required only for
converting a new raw PCAP.

### The incident does not appear

Run **Start live IP simulation** again. Replaying the same evidence is safe and
does not create duplicate incidents.

### Full recovery and presentation guide

See [`docs/FINAL_JUDGE_DEMO_GUIDE.md`](docs/FINAL_JUDGE_DEMO_GUIDE.md).

## Documentation

- [SIEM export contract and validation (Sprint 18)](docs/SPRINT_18.md)
- [Coordinated same-engine recovery (Sprint 17)](docs/SPRINT_17.md)
- [Protected access, signed evidence and retention (Sprint 13)](docs/SPRINT_13.md)
- [Continuous ingestion and recovery (Sprint 12)](docs/SPRINT_12.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build walkthrough](docs/BUILD_WALKTHROUGH.md)
- [Sprint plan](docs/SPRINTS.md)
- [Current status](docs/STATUS.md)
- [Production limitations](docs/PRODUCTION_LIMITATIONS.md)
- [Prototype requirements traceability](docs/PROTOTYPE_REQUIREMENTS.md)
- [Models and engineered features](docs/MODELS_AND_FEATURES.md)
- [Final SIH demonstration guide](docs/FINAL_JUDGE_DEMO_GUIDE.md)
