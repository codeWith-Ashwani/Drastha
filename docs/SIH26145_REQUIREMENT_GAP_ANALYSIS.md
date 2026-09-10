# SIH26145 requirement and gap analysis

## Executive verdict

Drastha implements every major software capability explicitly named in SIH26145: passive ingest, incremental feature extraction, all six required threat families, structured alerts, confidence/evidence, incident correlation, replay/live visualisation, data-quality handling and a measured throughput target. The core prototype is therefore **functionally SIH-complete**.

That does not mean every claim has equally strong experimental proof. The present release relies on a mixture of real Zeek/PCAP evidence, collector-decoded flow fixtures, deterministic attack-equivalent metadata and public-corpus research. The honest assessment is:

- **Named functional coverage: 100%** — every required capability family exists in the source and is exercised by automated tests.
- **SIH evidence maturity after Sprint 34: 89/100** — strong reproducible prototype evidence, with focused encrypted-traffic, interoperability and generalisation gaps listed below.
- **Production readiness: intentionally not claimed** — the signed release manifest correctly reports `production_ready: false`. Production hardening is outside this SIH-only assessment.

The most important remaining SIH work is not another dashboard feature. Sprint 34 now supplies isolated real-tool Slow HTTP, iodine and C2-timing evidence; the next priority is measured malicious/benign TLS or QUIC evidence and stronger independent DGA/C2 generalisation without inflating the accuracy claim.

## Source and interpretation note

The official SIH portal rejected automated retrieval during this review. The problem statement was therefore checked against two preserved community archives that identify the official portal as their source: the current [SIH26145 Markdown archive](https://github.com/vedantchalke36/sih-2026-problem-statements/blob/main/ps_2026/SIH26145.md) and an earlier [full SIH 2026 JSON snapshot](https://raw.githubusercontent.com/Sourav112-droid/sih-2026-problem-statements/refs/heads/main/data/sih-2026.json). Their SIH26145 text agrees on the background, objective, threat classes, expected solution and constraints.

The dataset-guidance field in the current archive ends mid-sentence at “Feature extraction: Extract flow”. This report treats only the visible wording as authoritative and does not invent the missing continuation. The named tools are treated as recommended ways to generate evaluation traffic, not as a requirement to ship or execute every tool inside Drastha.

## What the problem statement requires

SIH26145 describes a monitoring enclave that receives a one-way copy of network traffic through passive mirroring or a hardware data diode. The analytics system may observe PCAP, NetFlow/IPFIX/sFlow and derived metadata, but it must not contact the source or destination, complete handshakes, decrypt payloads, block traffic or push mitigation through the ingest path.

The required software flow is:

```text
One-way network copy
        |
        v
PCAP / flow exports / derived metadata
        |
        v
Read-only incremental normalisation and data-quality checks
        |
        v
Threat-specific feature extraction and inference
        |
        v
Standard alert: time + flow ID + class + confidence + evidence
        |
        v
Correlation into incidents and dashboard visualisation
```

The six required detection families are:

1. Volumetric/protocol DDoS: SYN floods, UDP reflection/amplification and suspected spoofed-source floods using flow rate and source-IP entropy.
2. Botnet C2 beaconing: periodicity and inter-arrival regularity toward a small destination set.
3. DGA domains and DNS tunnelling: domain entropy/n-grams, query length and record-type anomalies.
4. Malware-like anomalies in encrypted sessions: TLS/QUIC metadata, fingerprints and packet-size/timing sequences without decryption.
5. Reconnaissance and port scanning: source fan-out across destination ports or hosts.
6. Data exfiltration: outbound/inbound asymmetry and unusual flow volume.

## Requirement-by-requirement comparison

Status meanings: **Complete** means the capability exists and is exercised; **Partial evidence** means it works in the prototype but the real-world validation surface is narrower than the PS context; **Gap** means no adequate implementation was found.

| SIH26145 requirement | Drastha implementation and evidence | Status | Remaining limitation |
|---|---|---:|---|
| One-directional, passive operation | `analysis_service.py` publishes a read-only safety contract; detectors consume supplied observations only and contain no probing or mitigation path. | Complete | A physical TAP/data-diode deployment has not been demonstrated. |
| PCAP input | Classic PCAP is accepted directly or passed through Zeek; Sprint 19 and Sprint 31 include real PCAP-to-Zeek-to-dashboard evidence. | Complete | Direct parser lacks PCAPNG, fragmentation, non-Ethernet and advanced IPv6 support. |
| NetFlow/IPFIX/sFlow | `ingestion/flow_exports.py` normalises collector-decoded JSON/NDJSON representations of all three. | Partial evidence | No raw binary datagram decoder or independent exporter/vendor interoperability capture. |
| Derived metadata | Zeek connection, DNS and encrypted-session records are normalised into a common event model. | Complete | Sensor coverage still determines which metadata is available. |
| Never re-contact endpoints | No detector or replay path sends traffic to observed endpoints. The safety contract reports no return path/source contact. | Complete | Needs deployment/network-namespace or physical diode proof for a field claim. |
| Never complete handshakes | Analysis operates on observed records; it does not create transport sessions. | Complete | Same deployment-proof limitation. |
| No inline mitigation | Output is intelligence only: alerts, incidents, evidence and exports. | Complete | None for SIH scope; adding active blocking would be out of scope. |
| Streaming/incremental processing | Stateful sliding-window detectors process each record; SSE demo exposes findings before stream completion. | Complete | Demonstrated stream is simulated/in-process rather than a sustained live mirror. |
| Bounded latency | Sprint 24 sustained 50 records/s for 60 seconds over 3,000 mixed records, with about 111 ms p95 visibility latency and zero final backlog. | Complete | TestClient/prepared-metadata result is not an end-to-end link-through-Zeek benchmark. |
| Defined throughput target | Release documentation explicitly claims only the passed 50 records/s target. | Complete | A 100 records/s attempt missed the strict producer-lag gate; it is correctly not claimed. |
| Standard alert schema | `drastha-alert-v1` exports timestamp, flow identifier, threat class, confidence and supporting evidence, plus provenance and confidence semantics. | Complete | Confidence is a heuristic evidence score, not a calibrated attack probability. |
| Model/features/training/validation documentation | `MODELS_AND_FEATURES.md`, sprint reports, manifests and signed audits document detectors, data and promotion decisions. | Complete | Public-corpus generalisation shows weaknesses, especially DGA and CTU-13 C2/botnet traffic. |
| Dashboard live/replay detections | React dashboard supports upload replay, SSE demo, severity, confidence, evidence, incident conclusions, overall risk and SIEM export. | Complete | Browser/judge-machine rehearsal remains operational presentation work. |
| Alert persistence and API | SQLite and PostgreSQL stores, run-scoped analysis, incident APIs, feedback, status changes, metrics and JSON/NDJSON exports exist. | Complete | External SIEM connector interoperability is not the same as export-file support and is not required by the PS. |
| Data quality | Required fields, invalid records, duplicates and input timestamp order are checked before detector-side sorting; bad telemetry is not silently made healthy. | Complete | Quality remains dependent on truthful source timestamps and identifiers. |

No mandatory software requirement is wholly absent. The partial rows concern breadth of evidence and interoperability, not a missing core pipeline.

## Detection-family comparison

The thresholds below are detector defaults unless stated otherwise. The demonstration profiles intentionally use smaller recon and SYN thresholds so a compact replay can visibly cross a boundary; these are documented as demo values, not production calibration.

| Required threat | How Drastha detects it | False-positive controls | Evidence status |
|---|---|---|---|
| SYN flood | Five-second destination window; at least 100 SYN attempts by default, at least 80% incomplete connections and at least 80% concentration on a target port. | Port concentration separates a flood from broad port fan-out; completed-connection ratio and destination grouping add context. | Mixed evaluation produces the intended SYN/DDoS behaviour. Actual hping3-to-PCAP-to-Zeek ingest is demonstrated, but the sensor anchor is small and is not a broad attack benchmark. |
| Distributed/suspected spoofed-source flood | Adds at least three sources and normalised source-IP entropy of at least 0.85 to the SYN evidence. | Dashboard label is **Distributed-Source SYN Flood**. Evidence explicitly says passive data supports but cannot prove spoofing. | Correct and scientifically cautious. No claim of definitive spoof verification. |
| UDP reflection/amplification | Five-second target window, high UDP packet rate; reflection route requires at least four flows, recognised reflector service/port, response volume and at least 10:1 amplification ratio. | Requires reflection/amplification-specific evidence rather than generic UDP volume alone. | Intended mixed behaviour is detected. Real dnscat/reflection infrastructure is not part of current capture evidence. |
| Slow HTTP exhaustion | Additional PS-dataset-guidance coverage: many long-lived, low-byte, incomplete HTTP flows inside a window. | Requires duration, packet/byte and application-response evidence; wording does not claim the executable was identified from metadata. | Sprint 34 adds an actual isolated `slowhttptest` Slowloris-mode capture through tcpdump, Zeek and upload analysis. |
| C2 beaconing | Six or more completed repeated connections in 300 seconds, mean interval 2–120 seconds, interval CV no more than 0.15, size CV no more than 0.20, at least 30 seconds span and small mean transfer. | DNS is excluded from this detector; exact trusted health-check policy suppresses known operational periodic traffic; TLS metadata may adjust confidence but cannot trigger C2 alone. | Sprint 34 adds an isolated deterministic timing emulator and a jittered benign health control. It is not malware-family proof, and CTU-13 still exposes weak generalisation. |
| DGA | Character n-gram model score, or a cautious multi-domain lexical fallback combining distinct roots, entropy, digit ratio and vowel ratio. | A single random-looking name is insufficient for the fallback; model limitations and non-calibrated confidence are displayed. | Functional replay passes. The bundled model is explicitly demo-grade. Multiple public-corpus candidates failed frozen promotion gates, so production-quality DGA ML must not be claimed. |
| DNS tunnelling | Per-source/base-domain window with query count, unique subdomains, average label length/entropy and TXT record ratio; a strong encoded-TXT path uses four or more high-entropy, long TXT queries. | Combines several DNS-specific signals and scopes them by source/base domain. | Sprint 34 establishes an actual isolated iodine tunnel, carries ping and detects it through native Zeek TXT metadata. |
| Encrypted-session anomaly | Four repeated sessions in 60 seconds sharing an endpoint/fingerprint; fingerprint prevalence no more than 1%, packet-size anomaly at least 0.75 and timing anomaly at least 0.75. A causal median/MAD baseline is learned only from prior comparable sessions. | Fingerprint rarity alone cannot alert; warm-up/insufficient evidence is reported instead of turning missing features into zero; wording says “metadata anomaly consistent with malware”, not “malware detected”. | Required logic and replay evidence exist. Native parser computes limited JA3 only for a complete cleartext ClientHello in one TCP segment; native JA3S/JA4/QUIC extraction and independent malicious TLS/QUIC corpus evidence remain gaps. Trusted upstream JA3S/JA4 metadata is accepted. |
| Reconnaissance/port scan | Ten-second source window; default threshold of 20 unique ports or 20 unique hosts; classifies vertical, horizontal or multi-host fan-out. | Destination-port fan-out is used explicitly; authorised-scanner policy suppresses exact known scanners; historical threshold-crossing replay alerts are preserved. | Mixed and policy-control evaluation passes with no labelled benign false positive. |
| Data exfiltration | Five-minute source window; at least three flows, at least 1 MiB outbound, at least 8:1 outbound/inbound ratio and at least 4x the historical median; separate extreme single/baseline-free paths require 10 MiB and 20:1. | Approved source/destination/service policy suppresses known backups; network scope determines actual outbound direction; baseline and volume prevent ratio-only alerts. | Mixed attack is detected and approved backup remains benign in the pinned-context audit. |

## AI/ML truth: what is model-based and what is not

Drastha is correctly a **hybrid AI-assisted system**, not a project that forces a supervised classifier onto every threat.

- DDoS, C2, DNS tunnelling, recon and exfiltration use explainable streaming statistical/rule detectors. These rules directly correspond to the features required by the PS.
- Encrypted-session analysis uses unsupervised, causal robust baselines over fingerprint prevalence and size/timing sequences.
- DGA includes a character 3-gram Naive Bayes demonstration model plus a multi-observation lexical fallback.
- Confidence is explicitly a bounded heuristic evidence score. It is not represented as a calibrated probability.
- Incidents are correlated from alert source identity and time overlap. The incident conclusion and overall risk are deterministic, evidence-based summaries; they are not proof of attacker identity or intent.

This architecture is defensible because labelled examples for every organisation and traffic environment are not assumed to exist, while the evaluator can inspect every trigger. The weak point is not the choice to use rules; it is the current DGA model's independent generalisation.

## Dataset-guidance audit

| Dataset/tool mentioned in the visible PS guidance | Used by Drastha? | Exact truth |
|---|---:|---|
| iperf3 benign load | Yes | Sprint 31 uses a local iperf3 capture as part of the real sensor-ingest anchor. |
| Ostinato or TRex benign load | No | The guidance uses “or”; iperf3 covers the named benign-load option. No need to add tools merely for logo-counting. |
| hping3 SYN/UDP floods | Partly | hping3 is used in the real local capture workflow. The current 45-record anchor proves tool-to-PCAP-to-Zeek-to-upload integration, not comprehensive DDoS accuracy. |
| Slowloris | Yes, equivalent named mode | Sprint 34 runs `slowhttptest` 1.9.0 in its documented Slowloris/slow-header mode inside the isolated lab. |
| dnscat2/iodine | Yes, iodine | Sprint 34 establishes an iodine tunnel and carries successful ping traffic through it. Raw PCAP remains local; derived Zeek evidence is committed. |
| Published DGA algorithms/DGArchive | Alternative public data used | UMUDGA and an independent ExtraHop corpus are pinned and audited. Research candidates were rejected when they failed frozen promotion gates. DGArchive itself is not claimed. |
| Sandboxed C2 emulator | Yes, bounded timing emulator | Sprint 34 captures eleven real TCP callbacks at three-second intervals. It proves timing behaviour, not an actual malware family/framework. |

The semantic-equivalent corpus is useful because it is deterministic, safe and tests exact thresholds. It must be presented as unit/integration evidence, not passed off as traffic captured from the named attack tools.

## What is already strongly demonstrated

### Clean eight-behaviour evaluation

The actual HTTP upload-analysis path has two clean evaluations:

- 452-record chronological mixed replay: 8 findings, 8 incidents, 8 TP, 0 FP, 0 FN, 86 TN, healthy quality.
- 153-record identity-separated replay: the same eight expected behaviours, 0 FP and 0 FN, healthy quality, with attack and benign identities separated to reduce state-contamination risk.

The eight expected behaviours are distributed-source SYN flood, UDP reflection/amplification, multi-host port scan, periodic C2 beacon, DGA-like domains, DNS tunnelling, encrypted-session metadata anomaly and outbound-volume exfiltration anomaly.

This demonstrates deterministic behaviour-level correctness on the curated fixtures. It does **not** equal a universal 100% real-network accuracy claim.

### False-positive hardening

The 13-scenario Sprint 22 corpus contains 392 records. With no environment policy it deliberately shows that legitimate health checks, backups and scanners resemble attacks. With the pinned exact-match context policy, the result moves from 9 TP/3 FP/0 FN to 9 TP/0 FP/0 FN while five benign controls remain benign. Uploaded records cannot self-assert trust; suppression comes from operator-owned configuration.

This is a strong design choice: behaviour supplies suspicion, while trusted operational context changes the decision. The remaining risk is policy maintenance and untested benign diversity.

### Real sensor and ingest evidence

- Sprint 19 proves actual Zeek 8.0.10 processing of PCAP into connection, DNS and TLS logs, followed by the real dashboard analysis path with healthy quality.
- Sprint 31 proves a local authorised tool chain using iperf3, hping3, tcpdump and Zeek, plus collector-decoded NetFlow/IPFIX/sFlow examples.
- Checksums and manifests make the inputs and outputs reproducible.

These tests prove integration. Their small, local/loopback nature means they should not be described as a representative critical-infrastructure deployment trial.

### Streaming and throughput

Sprint 24 processes 3,000 mixed connection/DNS/encrypted records at a paced 50 records/s for 60 seconds, with all records observed, zero final backlog, healthy quality and about 111 ms p95 alert-visibility latency. A stricter 100 records/s experiment did not meet the producer-lag gate, so the release correctly claims 50 records/s rather than selecting a flattering number.

This satisfies the PS requirement to state and demonstrate a throughput target. It is still a metadata/API-path benchmark rather than Mbps measured from a real mirrored link through Zeek.

## Evidence that prevents an inflated claim

The project records negative results instead of hiding them:

- CTU-13 scenario 11 produced 0 malicious-flow TP, 15 verified-normal FP, 8,164 FN and 2,694 TN, with a large unknown-label population not relabelled. This is evidence that the current C2/botnet logic does not generalise to all botnet behaviour.
- The first public UMUDGA evaluation detected only 18 of 2,000 malicious final-test domains.
- Later family-separated DGA candidates improved some development metrics but failed the frozen promotion criteria. A three-fold experiment could not be called a clean holdout after all UMUDGA families had been inspected.
- Independent ExtraHop evaluation reached 63.36% recall with 6.80% false-positive rate and was rejected.

Therefore the evaluator-safe statement is: **Drastha detects the required behaviours on its controlled and mixed fixtures, has strong regression coverage, and includes a demo DGA model; independent generalisation remains research work.** Do not say “the ML model has 100% accuracy.”

## Transparent 89/100 SIH evidence score

This score measures how convincingly the current repository proves the PS, not how many source files exist.

| Area | Weight | Score | Reason |
|---|---:|---:|---|
| Passive architecture and ingest | 20 | 17 | Read-only design and real PCAP/Zeek proof are strong; physical diode/live mirror and raw flow-exporter interoperability are absent. |
| Six required threat families | 36 | 33 | All are implemented; actual Slow HTTP, iodine and C2-timing evidence now exists. DGA/C2 generalisation and native QUIC/JA4 evidence remain weak. |
| Alerts, incidents, API and dashboard | 18 | 18 | Required schema, evidence, confidence, replay/live views and persistence are present. |
| Streaming and performance | 10 | 7 | 50 records/s/60 s passes with bounded visibility; not end-to-end sensor/network throughput. |
| Validation, documentation and release reproducibility | 16 | 14 | Extensive tests, manifests, audits, real-tool evidence and a deterministic release exist; broader independent validation remains incomplete. |
| **Total** | **100** | **89** | **SIH-ready functional prototype with focused evidence work remaining.** |

The score deliberately does not award points for production-only work such as Kubernetes, SOAR blocking or enterprise HA because the user-defined goal is SIH compliance first and the PS expressly excludes mitigation across the ingest path.

## Remaining SIH work, in priority order

### Priority 0 — strengthen the weakest proof

1. Add a labelled malicious/benign TLS or QUIC metadata corpus containing measured fingerprints and packet timing/size sequences. Demonstrate warm-up, rarity and anomaly behaviour; do not inject final anomaly scores as if the detector measured them.

### Priority 1 — address generalisation honestly

2. Improve DGA using family-independent training/validation data and keep the existing frozen promotion gates. If no model passes, retain the current demo model but present it as a limitation rather than promoting it.
3. Add a second external C2/botnet corpus or scenario-level evaluation because CTU-13 shows that periodic-beacon rules do not cover arbitrary botnet traffic.
4. Expand benign controls: software updates, telemetry, CDNs, DNS security products, vulnerability scanners, large uploads and rare-but-legitimate TLS clients.

### Priority 2 — close architecture/interoperability evidence gaps

5. Import real collector outputs from at least one NetFlow/IPFIX exporter and one sFlow collector. Raw wire-protocol decoders are optional if the documented deployment boundary begins at the collector.
6. Extend the Sprint 34 no-default-route namespace proof with a physical one-way lab diagram or hardware data-diode evidence. Keep the software free of active response.
7. Repeat the 50 records/s test end-to-end from PCAP/Zeek or a live mirrored lab interface and report both record rate and approximate Mbps.

### Priority 3 — judge-day reliability

8. Rehearse the signed bundle on a clean Windows machine/browser, using the exact documented commands and fixtures.
9. Prepare a five-minute failure-tolerant demo: one clean mixed replay, one context false-positive comparison, one evidence drill-down, one SIEM export, and a pre-recorded fallback.

These nine items are evidence and delivery work. They do not require redesigning the detector architecture or adding attack categories outside SIH26145.

## Claims to use and avoid

Safe claims:

- “Drastha is a passive, read-only, streaming threat-intelligence prototype for one-way network observations.”
- “It implements all SIH26145 threat families using explainable behavioural statistics, contextual policy, a DGA n-gram model and unsupervised TLS/QUIC metadata baselines.”
- “The curated 452-record evaluation produces eight expected behaviour-level true positives with no labelled false-positive behaviours and healthy data quality.”
- “The demonstrated sustained target is 50 records per second for 60 seconds.”
- “Encrypted traffic is never decrypted; the result is an encrypted-session metadata anomaly, not definitive malware identification.”
- “Source diversity supports a distributed or possibly spoofed flood hypothesis, but passive observation cannot prove spoofing.”

Claims to avoid:

- “Drastha has 100% real-world accuracy.”
- “The DGA ML model is production-ready.”
- “JA3/JA4 identifies malware by itself.”
- “The system proves source addresses are spoofed.”
- “All NetFlow/IPFIX/sFlow exporters are supported at wire level.”
- “A physical data diode deployment has been validated.”
- “Drastha blocks attacks.” Blocking is intentionally outside the problem statement.

## Final conclusion

Drastha is no longer missing a core SIH26145 feature. It is a coherent working prototype with correct passive boundaries, all required detector families, a real upload/dashboard path, explainable evidence, contextual false-positive controls, automated evaluation, persistence, APIs and reproducible release artefacts.

Sprint 34 has now closed three visible real-tool gaps: DNS tunnelling, Slow HTTP and C2 timing plus a benign health control. The next winning move is malicious/benign TLS or QUIC metadata evidence. DGA and CTU-13 results must remain explicitly qualified until independent generalisation improves. End-to-end sensor throughput and physical one-way evidence would strengthen the submission further without drifting into production-only scope.

## Repository evidence reviewed

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/MODELS_AND_FEATURES.md`
- `docs/INGESTION_AND_VALIDATION.md`
- `docs/PROTOTYPE_REQUIREMENTS.md`
- `docs/SPRINT_9.md` through `docs/SPRINT_33.md`
- `src/aegisflow/analysis_service.py`
- `src/aegisflow/analysis_session.py`
- `src/aegisflow/passive_features.py`
- `src/aegisflow/detectors/`
- `src/aegisflow/ingestion/`
- `src/aegisflow/models.py`
- `src/aegisflow/incidents.py`
- `src/aegisflow/api.py`
- `src/aegisflow/api_store.py`
- `src/aegisflow/postgres_store.py`
- `data/manifests/sih26145-lab-v1.json`
- `data/manifests/sih26145-input-compliance-v1.json`
- `data/manifests/sih26145-final-validation-v1.json`
- `data/manifests/drastha-sih-release-v2.json`
- `output/sprint19_sensor_integration.json`
- `output/sprint22_hardening_audit.json`
- `output/sprint24_performance_audit.json`
- `output/sprint31_input_compliance_audit.json`
- `output/sprint32_sih_validation_audit.json`
- `output/sprint33_release_audit.json`
- `output/sprint33_bundle_audit.json`
- `output/sprint34_real_tools_audit.json`

## External sources

1. [SIH26145 problem statement archive, current Markdown](https://github.com/vedantchalke36/sih-2026-problem-statements/blob/main/ps_2026/SIH26145.md)
2. [SIH 2026 archived JSON snapshot containing SIH26145](https://raw.githubusercontent.com/Sourav112-droid/sih-2026-problem-statements/refs/heads/main/data/sih-2026.json)
3. [UMUDGA dataset publication](https://data.mendeley.com/datasets/y8ph45msv8/1)
4. [ExtraHop DGA Detection Training Dataset](https://github.com/ExtraHop/DGA-Detection-Training-Dataset)
