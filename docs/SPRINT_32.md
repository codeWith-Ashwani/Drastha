# Sprint 32 — final SIH threat and evidence validation

## Outcome

Sprint 32 closes the SIH threat, false-positive, evidence, streaming and
performance acceptance matrix through one checksum-pinned validation command.
It does not tune a detector on evaluation labels, weaken data-quality checks or
claim production accuracy.

The audit sends both final evaluation fixtures through the actual FastAPI upload
endpoint, shared detector engine and SQLite repository. It then reads the saved
run, every incident evidence page and the SIEM export back through their API
routes. A separate SSE run verifies that findings are emitted incrementally
before the completion message.

## Final controlled results

| Replay | Records | Findings | Incidents | TP | FP | FN | TN | Quality |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Mixed chronological v3 | 452 | 8 | 8 | 8 | 0 | 0 | 86 | healthy |
| Identity-separated accuracy v2 | 153 | 8 | 8 | 8 | 0 | 0 | 107 | healthy |

Both report 100% behaviour-level precision, recall and F1, and 0% FPR. These are
small controlled scenario-unit metrics, not production or population estimates.
The second replay has no source identity reused across attack and benign units;
it corroborates that the mixed replay result is not dependent on identity reuse.

The separate 392-record SIH lab corpus remains 9 TP, 0 FP, 0 FN and 5 TN with
the checksum-pinned operator context. It covers single-source SYN flooding and
Slow HTTP connection exhaustion in addition to the eight-behaviour mixed replay.

## Required classification and wording

| Passive behaviour | Final `threat_class` |
| --- | --- |
| concentrated incomplete SYN attempts | Volumetric DDoS - SYN Flood |
| high-entropy distributed SYN sources | Volumetric DDoS - Distributed-Source SYN Flood |
| amplification-shaped UDP exchanges | Volumetric DDoS - UDP Reflection/Amplification |
| periodic low-variation callbacks | Botnet C2 Beaconing |
| algorithmically generated name characteristics | DGA Domain Activity |
| encoded/long repeated DNS labels | DNS Tunnelling |
| rare fingerprint plus size/timing anomaly | Encrypted-session metadata anomaly |
| destination host/port fan-out | Reconnaissance - Multi-Host/Port Scan |
| large asymmetric outbound volume | Data Exfiltration - Outbound Volume Anomaly |

The distributed-source alert includes normalized source-IP entropy but explicitly
states that source diversity cannot prove spoofing. The encrypted alert remains
an anomaly consistent with suspicious activity and explicitly does not claim
definitive malware identification.

## Evidence and incident gates

Every alert must have the `drastha-alert-v1` schema, timestamp, primary and full
flow identifiers, specific threat class, bounded confidence, severity, supporting
evidence, limitations and a declaration that confidence is not probability.

Every alert maps to exactly one incident in these independent scenarios. Every
incident has an evidence-backed assessment, likely objective, attack stage,
potential impact, confidence basis and uncertainty. API incident detail is
verified to contain exactly the alerts referenced by that incident, preventing
the previous same-evidence-for-every-replay failure.

The replay-wide risk remains a bounded investigation priority. Both final
replays produce 88/100 critical overall priority, anchored by the strongest
incident plus capped incident-breadth and threat-diversity components. It is not
an attack probability and does not assert that separate incidents share one
operator.

## Passive and streaming contract

Every completed replay now exposes a machine-readable safety block:

```json
{
  "ingest_mode": "read_only",
  "passive_observation_only": true,
  "return_path_required": false,
  "source_or_destination_contacted": false,
  "payload_decryption_performed": false,
  "mitigation_command_issued": false
}
```

The actual simulated SSE path processes 67 connection, DNS and encrypted-session
observations, emits alerts before completion, and reports bounded near-real-time
passive processing. The previously signed sustained result remains 50 mixed
records/second for 60 seconds with 3,000/3,000 records observed, healthy quality,
zero final backlog and 111.25 ms P95 API visibility. This is metadata-pipeline
capacity, not live PCAP-to-browser or Mbps capacity.

## Reproduction

```powershell
.venv\Scripts\python.exe scripts\check_sprint32_sih_validation.py `
  --report-output output\sprint32_sih_validation_reproduction.json

.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The authoritative inputs and prior evidence are pinned by
`data/manifests/sih26145-final-validation-v1.json`. The checked-in result is
`output/sprint32_sih_validation_audit.json`.

## Boundaries

- No controlled-fixture metric is presented as real-world accuracy.
- Confidence remains a transparent heuristic evidence score, not probability.
- DGA research candidates remain unpromoted because they failed external gates.
- Raw binary flow datagram and broad exporter interoperability are not claimed.
- Physical data-diode deployment and production operations belong to the later
  production phase, not SIH prototype acceptance.

## Regression verification

- Final Sprint 32 acceptance audit: all gates passed.
- Full Python suite: 446 tests passed.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
