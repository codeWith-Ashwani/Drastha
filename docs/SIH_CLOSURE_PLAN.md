# SIH26145 closure plan — three gates, then stop

This plan supersedes open-ended “next sprint” work for the SIH submission. The
problem statement is the scope: passive one-way observation; the six named threat
families; incremental ingest and bounded-latency alerts; evidence, severity and
confidence on a replay or live dashboard; documented models/features/validation;
and a measured throughput target. Production deployment is not an acceptance gate.

The PS dataset field describes **sources to generate data**, not one supplied
benchmark file. It names alternatives (`iperf3`/Ostinato/TRex,
`dnscat2`/iodine, published DGA algorithms/DGArchive or a C2 emulator). Select
and document an actual source for each scenario. Do not claim that an alternative
ran when it did not. See the README provenance table for the current inventory.

## Gate 1 — analyst dashboard and evidence contract

- Make incident triage visible at the top of the dashboard: active and critical
  counts, last-run quality, explicit source mode, and highest-priority active
  cases. Preserve the existing replay, simulated stream, full investigation
  queue, evidence review, feedback, export, hero and visual theme.
- Distinguish API health from sensor health and simulated streaming from a real
  mirror. Risk is priority; confidence is not a calibrated probability.
- Keep the PS-source-to-fixture-to-test provenance in README. Run frontend tests,
  build and backend regressions. No new detector threshold changes in this gate.

## Gate 2 — fresh PS-source validation

- Generate **new**, independently labelled lab sessions using PS-listed options:
  `iperf3` benign load, `hping3` SYN and UDP attacks plus benign controls,
  `slowhttptest` Slowloris mode, iodine DNS tunnel, published-algorithm DGA
  samples, and the isolated C2 timing emulator. Existing 45- and 141-record
  captures are integration anchors, not a substitute for this fresh test.
- Include benign lookalikes and test all six required threat families. For TLS
  or QUIC, where the PS names metadata features but no generator, use a separately
  identified lab/corpus source with measured fingerprint, size and timing data;
  never treat supplied anomaly scores as measured features.
- Freeze raw capture hashes, labels, scenario identities and evaluation method
  **before** running the detector. Run the actual upload/incremental path and
  report per-family TP, FP, FN, TN and data quality, including failures. Keep
  452/153-record fixtures as regressions, not independent accuracy evidence.
- If an unexpected failure requires a fix, keep the failed result in the report,
  make the smallest PS-scoped correction and verify on another untouched session.

## Gate 3 — final SIH acceptance and release

- Rerun all fixed regressions, the frozen Gate 2 holdout, full Python/frontend
  suites, dashboard build, read-only/no-decryption checks and throughput proof.
- Audit every PS row against a source file, executable test or measured report.
  Mark weak evidence as a limitation; do not replace it with a synthetic 100%
  claim. Demonstrate the replay dashboard and evidence review from a fresh start.
- Commit the accepted source and documentation, make a reproducible release and
  stop SIH feature development. A failing gate is repaired **inside that gate**;
  it does not create Sprint 38. New production requests start a separate roadmap.

## Definition of done

The final report has a source/provenance matrix for every PS-guided dataset/tool,
measured results for all required threats and benign controls, the standard alert
fields, a passing streaming/latency/throughput demonstration, a usable SOC review
dashboard, and explicit limitations. “Complete” means the SIH prototype and its
evidence are reproducible; it does **not** mean field-certified detection accuracy
or a physical data-diode deployment.
