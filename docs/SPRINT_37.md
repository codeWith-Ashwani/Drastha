# Sprint 37 — final SIH acceptance decision

The executable final gate is `scripts/check_sih_final_gate.py`; its result is
`output/sih_final_gate_audit.json`. It reruns the existing checksum-pinned SIH
acceptance, the actual-upload fresh flow/metadata/DGA checks, the PCAP-enriched
TLS path, all Python and frontend tests, and the dashboard build. Its exit status
is **1 by design** when fresh-source evidence is incomplete; this is not a test
suite failure. `tests/test_sih_final_gate.py` asserts that a passing synthetic
demo cannot silently promote failing fresh holdouts.

## Measured result

| Gate | Result |
| --- | --- |
| Existing controlled eight-behaviour replays, passive-safety/schema, live-simulation path | Pass (prior `drastha-sih-v1.0` demo baseline) |
| Incremental sustained throughput | 50 records/s for 60 seconds, 3,000 records; p95 visibility 111.25 ms; max producer lag 99.78 ms (lab measurement, not field capacity) |
| Fresh `iperf3` / `hping3` / private UDP response shape | Pass: 768 accepted healthy records; 5 expected behaviours, 0 unexpected, 1 modest benign control clear |
| Fresh Slowloris-mode / C2 emulator / iodine | Pass: 136 accepted healthy records; 3 expected behaviours, 0 unexpected |
| Published DGA sample | **Fail**: 0 TP, 40 FN, 2 FP, 38 TN; healthy input, so this is model generalization, not data quality |
| PCAP-derived TLS changed-handshake control | **Measured but no positive**: 0 alerts, 6 prelabelled changed sessions missed, 0/110 baseline false alerts; 16 fully derived sessions, 100 baseline-warmup insufficient; no supplied scores or decryption |
| Full suites/build | 458 Python tests pass; 19 frontend tests pass; production dashboard build pass |

The TLS control is *not malware ground truth*. Its six changed TLS 1.3
handshakes had rare JA3 values but essentially normal measured first-eight-packet
size/timing (size score 0, timing about 0–0.01). The detector correctly requires
independent evidence rather than labelling rarity alone as malware. Thus this
test proves conservative measured feature extraction and exposes the absence of
a convincing **positive encrypted-session anomaly capture**. Its frozen label
was not changed after seeing the result; the six misses remain visible.

The current outcome is **functional SIH prototype with validation gaps**, not
full fresh-source SIH evidence or a production system. The implementation spans
all PS threat families, alert/evidence output, replay and simulated streaming,
but a successful controlled 452-record replay cannot substitute for DGA
generalization or a real measured TLS-positive scenario. A physical diode,
production sensor interoperability and calibrated attack probabilities are not
claimed. No new release tag was created or prior release rewritten. This closes
the planned two-sprint implementation/audit sequence without inventing another
open-ended sprint; the two explicit scientific evidence gaps remain recorded.

To rerun on this host:

```powershell
.venv\Scripts\python.exe scripts/check_sih_final_gate.py
```

It needs the local gitignored raw captures for full provenance and TLS PCAP
measurement. A fresh clone can run the committed fixture-hash tests, but cannot
claim a raw-capture recheck without regenerating independent sessions.
