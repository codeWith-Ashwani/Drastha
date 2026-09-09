# Sprint 25 — reproducible SIH prototype release validation

## Outcome

Sprint 25 turns the previous sprint outputs into one checksum-pinned acceptance
bundle. The release checker does not copy historical pass labels into a summary:
it verifies every evidence checksum, reruns the actual upload API accuracy replay,
reruns the context-hardening benchmark, audits the staged deployment contract and
revalidates the sustained-load evidence. It also serializes a real `Alert` object
to enforce the public alert schema.

The result is **submission demo ready** and deliberately **not production ready**.
That distinction is machine readable in both the release manifest and audit.

## Acceptance matrix

| Problem-statement requirement | Implementation | Reproduced evidence |
|---|---|---|
| Read-only, one-way ingest | File/Zeek adapters and passive analysis session; no detector callback path | Real offline Zeek integration records zero detector network attempts |
| No payload decryption | Zeek TLS metadata and header-derived packet sequences only | Sensor audit confirms payload is not decrypted or retained |
| Incremental streaming | Bounded follower, transactional checkpoint and atomic analyst projection | 60-second sustained run plus signed recovery drill |
| Defined throughput | Paced mixed connection/DNS/TLS metadata workload | 50 records/sec for 60 seconds; all 3,000 observed, zero final backlog |
| Standard alert records | `drastha-alert-v1` aliases over the internal alert contract | Timestamp, flow identifier, threat class, confidence and supporting evidence serialized |
| Threat classification | Threat-specific connection, DNS, TLS/timing and volume features | Nine lab behaviours detected, including Slow HTTP coverage |
| False-positive controls | Checksum-pinned operator context applied after behaviour detection | 9 TP / 0 FP / 0 FN / 5 TN on the controlled lab corpus |
| Dashboard and evidence | Authenticated analysis API, incident conclusions, telemetry and SIEM export | Eight-behaviour upload replay and JSON/NDJSON export both revalidated |

The nine lab behaviours are distributed-source SYN flood, UDP
reflection/amplification, Slow HTTP connection exhaustion, C2 beaconing, DGA,
DNS tunnelling, encrypted-session metadata anomaly, reconnaissance and data
exfiltration. The separate accuracy replay contains the eight problem-statement
behaviours and reproduces 8 TP / 0 FP / 0 FN with healthy input quality.

## Pinned release bundle

`data/manifests/drastha-sih-release-v1.json` records the release scope, baseline
commit, accepted claims, excluded claims and SHA-256 of ten evidence/configuration
artifacts. `scripts/check_sprint25_release.py` pins the manifest itself, refuses
duplicate or repository-escaping evidence paths, and fails on any content change.

Run the final machine gate from the repository root:

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sprint25_release.py
```

The generated result is `output/sprint25_release_audit.json`. A successful result
means the checked-in offline demo evidence is internally consistent and
reproducible on the current code. It is not a certificate for an operational
network.

## Honest boundaries

- The 9/0/0/5 and 8/0/0 results are small controlled lab results, not production
  accuracy or unknown-network generalization.
- Detector confidence is an explainable heuristic evidence score, not a calibrated
  probability that an attack occurred.
- The demonstrated target is 50 metadata records/sec for 60 seconds on one host.
  Two 100 records/sec attempts remain failed because producer scheduling lag
  exceeded the unchanged 100 ms gate.
- The DGA research candidate failed promotion gates and remains excluded from the
  staged deployment profile.
- Live mirror/data-diode, QUIC sensor, vendor SIEM delivery, SSO, external trust
  anchoring and automatic mitigation are not claimed.
- The staged internal CIDRs and context allowlist must be replaced and governed for
  a real enclave.

## Regression verification

- Sprint 25 release tests: 3 passed.
- Full Python suite: 415 passed.
- Frontend suite: 18 passed.
- TypeScript and Vite production build passed.
- The existing Starlette/httpx deprecation and Vite chunk-size warnings remain
  visible; neither was hidden by this sprint.
