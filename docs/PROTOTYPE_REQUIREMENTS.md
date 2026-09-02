# Drastha prototype requirements traceability

This document maps the passive cyber-threat prototype requirements to working
code, visible output, and repeatable verification. It describes the prototype;
it does not claim production accuracy or production-scale deployment readiness.

## One-way security boundary

Drastha consumes copied or simulated monitoring-side telemetry only. No detector
contains packet transmission, endpoint probing, handshake completion, blocking,
or mitigation code. The SSE channel is between the monitoring-side API and its
dashboard; it is not a path to any address represented by the telemetry.

- PCAP and Zeek adapters: `src/aegisflow/ingestion/`
- Mixed replay ingestion: `src/aegisflow/upload_analysis.py`
- Incremental simulated stream: `src/aegisflow/streaming_demo.py`
- API safety signal: `return_path_required: false`

## Threat coverage

| Required behaviour | Implementation | Main passive features |
|---|---|---|
| SYN flood | `detectors/ddos.py` | incomplete-flow ratio, attempt rate, target-port concentration |
| UDP flood | `detectors/ddos.py` | packet and byte volume inside a target window |
| UDP reflection/amplification | `detectors/ddos.py` | response/request byte ratio, flow count, target concentration |
| Distributed-source SYN flood | `detectors/ddos.py` | source diversity and normalized source-IP entropy; no spoofing claim |
| Botnet C2 beaconing | `detectors/c2.py` | inter-arrival mean/CV, observation span, size CV, completed-flow ratio |
| DGA-like domains | `detectors/dns.py`, `dns_model.py` | character 3-grams plus guarded lexical campaign fallback |
| DNS tunnelling | `detectors/dns.py` | query count, unique labels, label length, entropy, TXT-query ratio |
| Encrypted-session anomaly | `detectors/encrypted.py` | JA3/JA4 rarity plus packet-size and timing-sequence anomalies |
| Port/host scanning | `detectors/recon.py` | per-target, per-service, and combined multi-host/port fan-out |
| Data exfiltration | `detectors/exfiltration.py` | outbound volume, direction ratio, source baseline, extreme single- or multi-flow asymmetry |

Supplied replay fields named `label`, `threat_class`, and `confidence` are treated
as an untrusted answer key and are not used to create predictions. Monitoring-side
derived feature containers named `features`, `ml_evidence`, or `evidence` may
provide DNS/TLS feature values, but detector thresholds and confidence are always
recomputed by Drastha.

Legitimate operational context is supplied separately through the trusted local
`config/context_policy.json`. Rules match exact endpoint/service tuples and record
their purpose. Replay-supplied approval claims cannot suppress detections. The
dashboard reports how many connection evaluations matched approved policy.

## Streaming and bounded latency

`GET /api/stream/simulated` processes 67 connection, DNS, and TLS observations
incrementally. Each observation passes through the applicable stateful detector,
and an SSE alert is emitted immediately when its evidence crosses a threshold.
The final message reports processed records, alerts, incidents, elapsed time,
telemetry counts, `bounded_latency: true`, and the one-way safety properties.

Replay uploads also use the same threat-specific normalizers and detectors.
Threshold-crossing reconnaissance alerts are retained for the complete replay.
A final active-window snapshot is added only when it can enrich a still-active scan;
deduplication never deletes an earlier scan that has since expired from the window.

When optional `evaluation_*` ground truth is present, a post-inference scorer reports
TP, FP, FN, TN, precision, recall, F1, FPR, per-class coverage, and classification
mismatches. These fields are isolated from feature extraction and detector inference.

## Standard alert schema

Every `Alert.to_dict()` result includes:

- `schema_version`: `drastha-alert-v1`
- `timestamp`: alert observation-window end
- `flow_identifier`: primary contributing flow
- `flow_ids`: all contributing flows
- `threat_class` and `threat_type`
- `subtype`
- `confidence`
- `severity`
- `src_ip` and `dst_ip`
- `window_start` and `window_end`
- `supporting_evidence` and `evidence`
- `limitations`

The aliases preserve backward compatibility with the SQLite/PostgreSQL API while
providing a simple interoperable contract. `threat_type` remains the stable
machine family identifier, while `threat_class` is the presentation-ready,
subtype-specific classification (for example `Volumetric DDoS - SYN Flood`).

## No payload decryption

Encrypted-session analysis accepts visible TLS/QUIC metadata and derived timing or
packet-size features only. A JA3/JA4 fingerprint cannot trigger an alert alone.
Repeated sessions, rare prevalence, packet-size anomaly, and timing anomaly must
all be present. Alerts explicitly state that they are metadata hypotheses rather
than proof of malware.

## Throughput target and proof

The development target is **1,000 monitoring records per second** on the tested
machine. `drastha evaluate-demo` records an end-to-end prototype benchmark covering:

1. fixture file reads;
2. normalization;
3. detector and model inference;
4. correlation and risk scoring;
5. SQLite upserts;
6. SSE serialization.

It excludes physical capture, Zeek conversion, HTTP transport, and browser render
time. The generated report records the environment, iterations, total records,
median/P95 processing time, sustained records/second, target, and pass/fail result.
The recorded Windows/Python 3.12 run processed 16,750 records at 1,127.74
records/second (median 57.992 ms and P95 67.9 ms per 67-record iteration), so the
declared 1,000-record/second prototype target passed on that machine.

## Verification commands

```powershell
$env:PYTHONPATH = "src"
drastha evaluate-demo --iterations 250 `
  --report-output output/drastha_evaluation_report.json

python -m unittest discover -s tests -v

cd web
pnpm run build
```

Synthetic scenario validation proves deterministic implementation behaviour. Real
deployment accuracy still requires licensed datasets, deployment-specific benign
baselines, threshold calibration, drift monitoring, and operational validation.
