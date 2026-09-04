# Sprint 16 — integrity-preserving streaming optimization

## Scope

Optimize the measured continuous-ingest hot path without weakening source,
quality, provenance or signed-evidence checks. This is a bounded scaling slice,
not unlimited streaming or production readiness. Detector thresholds/models,
the 452-record fixture, public alert fields and dashboard content are unchanged.

## Changes

1. **Atomic analyst projection.** `IncidentRepository.project_analysis_run()`
   publishes incidents, alerts and the matching analysis-run snapshot using one
   connection/transaction. The signed repository verifies the full ledger and
   protected state on entry and signs the entire committed change set. Failures
   roll back all three outputs together. Existing import/report APIs remain;
   external repositories without the new method retain the legacy fallback.
2. **Remove a redundant state scan.** Signed transactions already compute an
   after-state snapshot. A third scan is now needed only if trusted retention
   bookkeeping actually writes additional data. Read operations and no-op
   publication still perform full before/after snapshots and full chain
   verification. No cached trust, timestamp shortcut or partial-chain check.
3. **Reuse normalization without the upload wrapper.** The follower's decoded
   JSONL object enters the same shared validation/event-normalizer loop directly.
   It no longer serializes and reparses a JSON container or builds an unused
   upload-schema summary for every line. Finite-JSON checks remain, including
   invalid floats in unused metadata. The shared one-record case avoids building
   a duplicate-UID signature map that cannot contain a duplicate; the follower
   still performs its full cross-record `(record kind, UID)` duplicate checks.
4. **Repeatable diagnostic.** `scripts/profile_stream_pipeline.py` records
   version/engine digest, counts, quality and cProfile hotspots over a bounded
   10,000-record signed run. It is explicitly not a sustained-throughput test.

The SQLite schema and HMAC format are unchanged. Atomic projection changes the
granularity of *new* audit entries from two transactions to one, not historical
entries. Previous databases/backup verification remain supported. PostgreSQL
inherits the connection-scoped upserts; no real PostgreSQL concurrency test was
performed. The measured and supported continuous worker remains local SQLite.

## What remains deliberately unchanged

- Every poll retries/verifies the previous analyst projection **before consuming
  new source bytes**. A tampered store is not silently repaired and re-signed.
- The complete committed source prefix is rehashed every poll, including idle
  polls. Replacement, truncation and same-size edits still stop the worker.
- FULL synchronous checkpoint commits, bounded batches/journal, arrival-order
  quarantine, preserved historical findings and full bounded recovery remain.
- Analyst status, feedback and retention holds survive republication. Run-level
  detection snapshots remain distinct from mutable analyst review state.
- Journal and analyst store are separate databases: delivery is still
  idempotent at-least-once, **not cross-database exactly-once**. Recovery republishes
  a committed journal after an analyst transaction rollback/process crash.
- Default batch 64 is unchanged, as are detector thresholds, quality standards,
  latency/producer-lag gates and workload/counts. A separately labelled batch-256
  experiment explores a bounded configuration trade-off; it is not substituted
  for the default-64 comparison and does not silently change the worker default.

## Measurements

The same finite 10,000-record diagnostic, batch 64, with cProfile enabled:

| Measurement | Before | Atomic projection only | Final normalization + projection |
|---|---:|---:|---:|
| Elapsed (profiler overhead included) | 12.228 s | 10.174 s | 9.420 s |
| Publication cumulative time | 4.011 s | 2.319 s | 2.302 s |
| Record consumption cumulative time | 6.213 s | 5.975 s | 5.282 s |
| Signed transaction/verification calls | 783 | 470 | 470 |
| Full row snapshot calls | 2,349 | 1,097 | 1,097 |
| Full source-prefix checks | 157 | 157 | 157 |

All runs accepted 10,000 records, rejected zero and reported healthy quality with
one resolved finding. Final elapsed was about 23% lower in this diagnostic.
Cumulative durations overlap and must not be added. Direct repository readback
is used, not API/TLS/browser transport. These single profiled runs do not establish
capacity, statistical significance or the isolated cost of each operation.

Raw reports: `output/sprint16_profile_before.json`,
`output/sprint16_profile_atomic.json`, `output/sprint16_profile_after.json`.
The before run uses the unchanged Sprint 15 engine. Each report pins its engine
digest; the middle run is an explicitly labelled development intermediate.

The default-64 **1,000 records/sec run still fails**. It now observes all 60,000
records within the drain deadline (previously 54,516 with 5,484 pending), but
requires 81.741 seconds overall/21.741 seconds drain. Only 47,026 were observed by
the 60-second offer-window end (previously 40,244). P95 visibility is 19,411.41 ms,
well above the 1,000 ms gate. Maximum producer scheduling lag also fails at
156.55 ms. The requested sustained target therefore remains unproven.

The new P95 covers all 60,000 records; Sprint 14's 32,365.30 ms P95 covered only
54,516 observed records, so do not present these as equal-denominator latency
distributions. Sampled peak RSS is 237.62 MiB and disk 30.88 MiB. The unchanged
load harness/workload hashes are retained in `output/sprint16_signed_1000rps_60s.json`.
This is an improvement, not a passing capacity result.

The separate **batch-256 experiment also fails overall**, but meets the API
visibility gate: 60,000 observed, 59,760 before offer-window end, P95 230.81 ms,
maximum 498.33 ms, and 0.214 seconds drain. Producer maximum scheduling lag is
176.54 ms, exceeding the unchanged 100 ms budget. All other gates pass: healthy,
zero rejected, source preserved, sampled peak RSS 234.47 MiB and disk 30.57 MiB.
See `output/sprint16_signed_1000rps_60s_batch256.json`. This is promising bounded
configuration evidence, **not** a passing sustained 1,000 records/sec result.
It must not replace the default-64 comparison or relax the producer gate.

The **100 records/sec, 60-second signed control passes all gates** with default
batch 64: 6,000 emitted/observed, zero backlog/rejections and healthy quality;
5,994 were observed by the offer-window end. P95 API visibility is 107.15 ms,
maximum 193.29 ms, and drain 0.071 seconds. This validates only the stated finite
synthetic conn/SQLite/ASGI workload, not production or packet-to-browser latency.
Raw report: `output/sprint16_signed_100rps_60s.json`.

## Regression coverage

Twenty new tests cover one verified transaction/audit event, parity with legacy
upserts, failure after evidence upserts, signing failure, isolation from concurrent
readers, repeat verification on identical publication, tampered historical chain
and current state, analyst state/holds, pre-consumption backpressure, full prefix
checks, abrupt child-process exit inside projection, exact normalization/quality
parity for all 452 records, invalid metadata, container refusal, legacy adapters
and engine-mismatch refusal, plus explicit batch-256 bounds/recovery and unchanged
full read-transaction verification. Existing fault-injection tests now target the atomic
transaction boundary and assert the stronger no-partial-evidence result.

Final verification on 4 September 2026:

- Full Python suite: **334 passed in 20.713 seconds**.
- Separate scaling/continuous/security/mixed subset: **72 passed in 7.907 seconds**.
- Actual upload/API and continuous restart parity: **452 accepted, 0 rejected,
  8 findings, 8 incidents, 8 TP, 0 FP, 0 FN, 86 TN, healthy**. Original fixture
  bytes unchanged; 47 journal records reconstructed after restart. This is
  behaviour-level synthetic evaluation, not generalization accuracy. Raw report:
  `output/sprint16_mixed_recovery_report.json`.
- Real loopback HTTPS upload/auth/backup/restore drill: **all nine gates passed**;
  25 scan records, healthy, exact evidence/run restored. Raw report:
  `output/sprint16_https_recovery_report.json`. This exercises analyst backup
  recovery, not coordinated journal migration or browser rendering.
- Existing working-tree frontend build and four theme tests passed. Pre-existing
  UI changes are preserved and excluded from this sprint commit; those frontend
  checks are not a claim of clean-checkout browser validation.
- A Starlette TestClient/httpx deprecation warning remains; no dependency upgrade
  or unrelated UI work is included in this performance slice.

## Upgrade/checkpoint decision

No checkpoint migration, compaction or digest override is implemented in this
sprint. The source engine changed, so an old continuous checkpoint must still
fail closed. Do not edit `engine_sha256`, clear a journal or reset state merely
to force a new binary to resume. Follow the existing [operations
runbook](OPERATIONS_RUNBOOK.md) and retain the exact old release for rollback.

A future migration must be a separately approved, create-only operation: freeze
source/journal at an explicit cut, retain originals, verify old source and journal
digests, prove record dispositions/alerts/provenance equivalence through the old
and new engines, reconcile analyst review state, and publish a signed migration
receipt before manual cutover. Changes in normalizer/detector semantics must fail
that equivalence gate rather than being hidden by an engine-hash replacement.
Cross-store recovery, live rotation and unbounded state remain unresolved.

## Reproduce

Run sequentially, in fresh processes, using new output names:

```powershell
.venv\Scripts\python.exe scripts/profile_stream_pipeline.py --report-output output/profile-new.json
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 1000 --seconds 60 --signed --report-output output/load-1000-new.json
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 1000 --seconds 60 --signed --batch-records 256 --report-output output/load-1000-batch256-new.json
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 100 --seconds 60 --signed --report-output output/load-100-new.json
.venv\Scripts\python.exe scripts/check_continuous_ingestion.py --report-output output/mixed-new.json
.venv\Scripts\python.exe scripts/check_operational_recovery.py --report-output output/recovery-new.json
.venv\Scripts\python.exe -m unittest tests.test_scaling_sprint16 tests.test_continuous_ingestion tests.test_security_sprint13 tests.test_mixed_evaluation_replay -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Original Sprint 14 failed measurements remain unchanged. Real Zeek, browser QA,
model generalization, multi-sensor/state retention and remote operational
deployment are still open; an improvement here does not certify those gates.
