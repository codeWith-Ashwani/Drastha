# Sprint 12 — bounded continuous ingestion and recovery

Delivered 4 September 2026: an operator-run, append-only JSONL follower sharing
the existing normalization and `AnalysisSession` detectors, with durable commit,
bounded read-ahead, strict late-record quarantine and restart verification.
**This completes the bounded single-source recovery slice, not an unlimited
production streaming service.** Sprint 11's failed research model stays unpromoted.

## Execution and durability

`read-only local JSONL -> bounded batch -> shared normalization -> arrival-order
validation -> AnalysisSession -> atomic journal/checkpoint/evidence snapshot ->
idempotent analyst-store projection -> existing incident and analysis-run APIs`

Only the local monitoring-enclave file is opened, in binary read mode. No probe,
source/destination query, payload decryption or mitigation command is issued.
The producer must supply one complete JSON object per newline, using the existing
connection/DNS/TLS/QUIC metadata fields and aliases. Blank/comment lines count as
physical journal lines, not telemetry records. UTF-8 BOM is allowed only at the
start. Arrays, wrapper objects and manifests remain finite-upload formats, not
stream records. A partial last line remains uncommitted until its newline arrives.

Each poll reads at most `batch_records` complete lines before processing them.
There is no unbounded producer thread or in-memory queue. When the consumer or
analyst store is slow/unavailable, unread bytes stay in the local source file.
That is local pull-side backpressure, **not flow control across the data diode**;
the upstream sensor can still overrun its own storage. No end-to-end losslessness
claim is made. Queue high-watermark and unread byte backlog are reported.

SQLite commits the raw records (including quarantine), decisions, byte offset,
source-prefix SHA-256 and latest findings/incidents snapshot in one transaction,
using `synchronous=FULL`. A separate SQLite exclusive lock permits one writer per
journal; OS process termination releases it. Before commit, a failure rolls back
the entire batch; the in-memory worker then becomes unusable and must reopen.
After commit, delivery failure leaves a durable snapshot to retry on restart.
Source bytes are never changed or acknowledged upstream.

The optional analyst SQLite database is a projection, not the authoritative
checkpoint. Import uses existing stable alert/incident IDs and preserves analyst
review status. Records and report are not a cross-database atomic transaction:
delivery is **at-least-once with idempotent upserts**, not distributed exactly-once.
No new source-accessible HTTP control endpoint is introduced. The existing
`GET /api/incidents` and `GET /api/analysis-runs/{run_id}` expose persisted results.
Run IDs start with `stream-`. Journal snapshots, CLI reports and the API report
include quality, provenance, queue/backlog, commit position and `updated_at`.
The current dashboard can review projected incidents; this sprint does not add a
stream-management screen or guarantee automatic UI refresh.

## Recovery and input integrity

Restart checks the resolved source identity, entire committed prefix hash,
journal continuity and hash, source code digest, schema, detector configuration,
model, policy and resource limits. It then replays the complete bounded journal
through fresh detectors, checking each normalization/quarantine outcome and the
reconstructed alert snapshot. Windows, cooldowns and exfiltration baselines are
reconstructed together; no partial-state pickle or unsafe deserialization is used.
The prefix is checked again before every poll. Changes fail closed rather than
resetting the cursor, silently warming up again or changing old evidence.

Records are processed in original arrival order. Equal timestamps are permitted;
within a combined record TLS/DNS metadata precedes its connection. Independent
same-time records are **not retrospectively reordered**: a later TLS record cannot
enrich an already-processed connection. A timestamp below the observed high-water
mark is counted and quarantined, not silently sorted. Duplicate detection uses
`(record kind, UID)`, so genuine DNS and connection records sharing a Zeek UID are
allowed; repeated/conflicting UIDs within a kind are counted and quarantined.
This deliberately stricter streaming policy does not alter finite upload sorting.

Every rejected record is stored with raw bytes and a reason in `stream_records`.
Reports show at most five error strings and twenty quarantine examples; total
counters are not truncated. Zero accepted records or a rejection ratio above
10% yields `unusable`; any other rejection yields `degraded`. Missing evidence is
not treated as benign. Live late/duplicate records remain in the denominators.
Oversized physical lines stop the worker without advancing past them.

Checkpoint or source tampering, truncation or replacement stops processing.
Hashes detect inconsistency, **not malicious rewriting and re-signing by someone
who controls the local files**. Tamper-evident evidence and access control remain
Sprint 13 work. Treat journal files as sensitive traffic, not safe-to-share reports.

## Limits and operational semantics

Defaults are 64 queued lines, 256 KiB per line, 20,000 committed physical lines
and 64 MiB of committed source bytes per journal. The parser bounds each batch;
complete-journal recovery and total detector state remain bounded by these explicit
session budgets. These are input budgets, **not exact heap/disk caps**: Python
objects, evidence, SQLite indexes and the optional analyst projection add overhead.

At capacity, the worker reports `capacity_reached`, leaves pending bytes unread
and exits nonzero. There is no automatic pruning or rollover that would discard
baselines or detection history. An operator must retain the original journal/source
and plan an independently scoped new capture; do not call that seamless recovery.
Limits are pinned on first use and cannot be silently increased at restart.

State is not compacted; startup work is proportional to the committed journal.
Full-prefix verification and full snapshot/projection also grow with the session.
This is not a long-run throughput optimization. Multi-file sensor joining,
rotation handoff, state migration, unbounded-service retention, durable queue
brokers, HA/multi-host workers and measured overload capacity remain open.
Use local filesystems with reliable SQLite locks, not network shares. A stopped
worker may leave the API's last successful report stale, especially when projection
is unavailable; inspect `updated_at`, CLI errors and the local snapshot. A process
health signal must not be inferred from historical telemetry quality alone.

## Reproduce

One finite, repeatable drain (source remains read-only; paths must be distinct):

```powershell
.venv\Scripts\python.exe -m aegisflow.cli follow --input examples/drastha_mixed_evaluation_v3.jsonl --checkpoint output/sprint12-local.db --database output/sprint12-analyst.db --profile upload-demo --root . --once
```

Run the exact command again to resume without redetecting historical records.
Omit `--once` to keep following an append-only **monitoring-side** source; default
idle polling is 0.5 seconds. Stop with Ctrl+C. Exit 0 means the available complete
lines were drained, not that input quality or detections passed an accuracy gate;
inspect the report. Capacity/failure exits 2 and Ctrl+C exits 130. Without
`--database`, durable findings remain in the checkpoint snapshot and stdout only.
The API must be configured for the explicit analyst database to see that projection.

Use `deployment-baseline` (the default) and explicitly configured internal networks
for non-demo work; it is still uncalibrated. `upload-demo` above is only for existing
fixture parity. Never change source/model/policy/code under a checkpoint or remove
the journal to make a restart appear healthy.

```powershell
.venv\Scripts\python.exe scripts/check_continuous_ingestion.py
.venv\Scripts\python.exe -m unittest tests.test_continuous_ingestion tests.test_mixed_evaluation_replay -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The smoke script uses temporary sources/journals/analyst databases and compares
actual HTTP upload output with continuous ingestion plus API readback. It never
touches the operational database or modifies the original fixture. Optional
`--report-output` is create-only. The retained result is
`output/sprint12_recovery_report.json`.

## Measured acceptance

- 240 Python tests passed: 216 existing plus 24 new continuous-ingestion tests.
- Tests include a child process exiting abruptly **inside a SQLite batch**, lock
  release, pre-commit rollback, post-commit projection retry, analyst-review
  preservation, partial lines, byte/line budgets, late/duplicate/malformed input,
  same-UID cross-log records, source edits/rotation and checkpoint corruption.
- 452 accepted, zero rejected/late/duplicate records, eight findings, eight
  incidents; independent post-inference fixture scoring remains 8 TP, 0 FP,
  0 FN, 86 TN and healthy quality. All eight intended attack families retained.
- Restart after 47 lines; queue high-watermark 17 under a configured limit of 17.
- Finite smoke run: 1.0578 seconds, 427.31 records/sec; 44.599 ms restart recovery;
  poll P50/P95 25.329/30.238 ms across 38 polls. Includes appends, initialization,
  one restart, inference, durable journal and analyst projection; excludes the
  later HTTP comparison/evaluation. These are local measurements, **not sustained
  throughput, packet-to-alert latency, a service SLA or production capacity**.
- No detector threshold/model changes, no accuracy tuning, no background-image
  integration, no production-data migration, no live sensor or browser validation.

Sprint 14 still owns sustained-load and real-sensor measurement. Sprint 13 is the
next numbered sprint; the limits above and Sprint 11 calibration remain explicitly
open and cannot be hidden by the numbered sprint progression.
