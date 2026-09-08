# Sprint 20 — reproducible SIH-guided offline lab corpus

## Outcome

Sprint 20 adds a checksum-pinned, deterministic corpus that translates the
traffic-generation guidance in SIH problem statement 26145 into 13 safe offline
metadata scenarios. It contains 392 chronological Zeek-shaped records across
four benign controls and nine attack/coverage scenarios. Every artifact has a
separate ground-truth sidecar and is evaluated in a fresh detector session
through Drastha's shared analysis service.

This corpus does **not** claim that hping3, Slowloris, dnscat2, iodine, a C2
emulator, iperf3, Ostinato or TRex was executed. It creates deterministic
metadata-level semantic equivalents and never transmits attack traffic. The
separate Sprint 19 report remains the real Zeek 8.0.10 connection/DNS/TLS sensor
anchor; the manifest explicitly prevents that anchor from being misrepresented
as the source of every scenario.

## Corpus design

| Scenario | PS-guided analogue | Truth | Current baseline |
|---|---|---:|---:|
| benign load | iperf3 / Ostinato / TRex | benign | TN |
| periodic health check | operational monitor | benign | FP target |
| approved backup/update | approved bulk transfer | benign | FP target |
| authorized scanner | approved scanner | benign | FP target |
| SYN flood | hping3 SYN | attack | TP |
| UDP reflection/amplification | hping3 UDP/service response | attack | TP |
| slow HTTP exhaustion | Slowloris | attack | known FN |
| C2 beacon | sandboxed C2 emulator | attack | TP |
| DGA domains | DGA algorithms / DGArchive style | attack | TP |
| DNS tunnel | dnscat2 / iodine style | attack | TP |
| encrypted-session anomaly | TLS metadata only | attack | TP |
| reconnaissance | scanner fan-out | attack | TP |
| data exfiltration | unapproved asymmetric transfer | attack | TP |

The encrypted-session artifact includes 100 benign metadata sessions before
four anomalous sessions. This warms the real causal prevalence and robust
packet-sequence baselines. The detector derives fingerprint prevalence,
packet-size anomaly and timing anomaly from `packet_observations`; supplied
scores are neither needed nor accepted by the benchmark path.

## Reproducibility and safety controls

- `scripts/build_sih_lab_corpus.py` produces byte-identical files and refuses to
  overwrite existing corpus evidence. `--check` compares the checked-in corpus
  with a fresh in-memory build.
- `data/manifests/sih26145-lab-v1.json` pins SHA-256 for every telemetry and
  label file. `load_corpus` rejects changed files, repeated capture IDs,
  cross-split group leakage and normalized cross-split duplicates.
- Detector input contains only canonical passive telemetry. `label`,
  `expected_classes`, `evaluation_*` and `ml_evidence` are absent. Labels are
  read only after inference for scoring.
- Every artifact is chronological, has unique UIDs and includes `ts`, `uid`,
  `id.orig_h`, `id.resp_h` and `proto`. All 392 records are accepted and every
  capture reports healthy quality.
- No socket, active interface, attack binary, probe, payload decryption or
  mitigation path is used.

## Honest baseline result

`output/sprint20_lab_corpus_audit.json` records the full shared-path execution:

| Unit-level alert coverage | Result |
|---|---:|
| TP | 8 |
| FP | 3 |
| FN | 1 |
| TN | 2 |
| Precision | 72.73% |
| Recall | 88.89% |
| F1 | 80.00% |
| FPR | 60.00% |

The small unit count makes these descriptive lab results, not production
accuracy. The three false positives are deliberately difficult context controls
run with the benchmark's empty policy: a health check resembles C2, an approved
backup resembles exfiltration, and an authorized scanner resembles recon. The
Slowloris-style scenario is an explicit detection gap. The audit gates require
these limitations to stay visible instead of making metrics look better.

Sprint 22 owns contextual validation/hardening on unseen data. Sprint 20 does
not change detector thresholds or use labels during inference.

## Reproduction

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\build_sih_lab_corpus.py --check
.venv\Scripts\python.exe scripts\check_sih_lab_corpus.py `
  --report-output output\sprint20_lab_corpus_reproduction.json
```

Use a new report filename if retaining immutable evidence. The corpus builder's
normal mode is create-only.

## Next work

- Sprint 21: family-separated DGA development and calibration without test-set
  threshold selection.
- Sprint 22: context-aware false-positive hardening plus Slow HTTP coverage
  decision and unseen validation.
- Native NetFlow/IPFIX/sFlow capture adapters, QUIC sensor interoperability and
  physical data-diode deployment remain outside this corpus proof.

## Regression verification

- Deterministic corpus check: 13 scenarios reproduced byte-for-byte.
- Targeted corpus/benchmark/mixed-replay suite: 32 tests passed.
- Full Python suite: 393 tests passed in 36.309 seconds.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
- The existing Starlette/httpx deprecation and frontend HMR-port warnings remain
  visible; no test or quality gate was disabled.
