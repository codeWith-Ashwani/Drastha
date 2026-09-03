# Sprint 8 — Shared analysis pipeline

Status: implementation and acceptance verification complete, 4 September 2026.
Source-control author identity is confirmed as codeWith-Ashwani.
This sprint does not claim production readiness; Sprints 9–15 remain separate work.

## Architecture

Input adapters (HTTP upload, CLI file, Zeek directory, simulated SSE)
→ shared passive-replay validation and normalization
→ deterministic event-time ordering
→ isolated AnalysisSession
→ shared finding resolution and incident correlation
→ persistent evidence and analysis-run snapshots
→ JSON response / SSE / CLI report.

- `ingestion/passive_replay.py`: alias resolution, schema routing, atomic record
  projection, original-order quality accounting, and event ordering.
- `analysis_session.py`: immutable profiles, all detector construction, observed
  TLS context, typed dispatch, final finding resolution and incident correlation.
- `findings.py`: existing conflict resolution and deduplication, now shared.
- `analysis_service.py`: completed analysis, evaluation and persistence.
- `replay_service.py`: file and Zeek-directory adapters.
- `upload_analysis.py`: HTTP-facing extension/size limits only.
- `streaming_demo.py`: provisional live notifications and authoritative completion.
- `cli.py`: shared-engine commands; explicit persistent exfiltration state retained.

## Acceptance gates

- [x] Equivalent serialized findings and incidents for identical events, profile,
  model and trusted context across HTTP upload, streamed replay and CLI file adapter.
- [x] All 452 mixed-fixture records preserved: 8 findings, 8 incidents, 8 TP,
  0 FP, 0 FN, 86 TN and healthy quality.
- [x] Original-order quality checks retained before sorting; out-of-order input
  remains degraded in both upload and streaming.
- [x] Every independent replay gets separate windows, cooldowns and baselines.
  Completed sessions reject reuse; finalization is idempotent.
- [x] Historical recon detections survive active-window expiry. Final snapshots
  enrich history instead of replacing it.
- [x] Named compatibility and deployment-baseline profiles; explicit operator
  profile selection, never controlled by uploaded answer keys.
- [x] DNS query aliases, numeric/named query types and response codes normalized
  through the same implementation. TXT=16 and NOERROR=0 are preserved.
- [x] Native TLS-only observations do not invent connection records. Mixed
  connection-plus-TLS records are validated atomically before either projection
  enters detection. Known Zeek log types are supplied by the file adapter.
- [x] TLS context is derived only from observations seen by the current event
  time, bounded to the C2 observation window, and matched by UID plus endpoints.
  Future metadata does not influence an earlier alert.
- [x] Equal-time metadata is ordered before connections; late events passed
  directly to a session fail explicitly. Finite replay adapters sort only after
  recording input-quality faults.
- [x] CLI replay, DNS, C2, exfiltration and instant replay use the shared engine.
  Existing CLI detector selection, threshold flags, allowlists and explicit
  exfiltration state restore/save remain supported.
- [x] PCAP all-threats adapter accepts generated conn/DNS/SSL/QUIC logs.
- [x] Configuration, model, policy and detector provenance is included in alert
  records and survives storage, restart and incident export.
- [x] Model artifact selection is configurable; an explicitly missing model is
  an error rather than a silent fallback.
- [x] Provisional stream snapshots and completed analysis runs are durable and
  separate from the final incident tables.
- [x] Dashboard replaces provisional findings with the authoritative completion
  snapshot and uses reported telemetry quality instead of hard-coding healthy.

## Profiles and model selection

Default HTTP upload uses `upload-demo-v1` (recon fan-out 5); simulation uses
`stream-demo-v1` (fan-out 6). These explicitly preserve existing entry-point
behaviour. Parity requires selecting the same profile. Neither is production
calibrated. `deployment-baseline-uncalibrated-v1` uses existing detector defaults.

For both HTTP paths, set trusted environment variable `DRASTHA_ANALYSIS_PROFILE`
to `upload-demo`, `stream-demo`, or `deployment-baseline`. Unknown names fail.
Python callers may pass a complete immutable AnalysisProfile with custom
detector configs. CLI legacy flags are translated into explicit profiles.

`DRASTHA_DNS_MODEL` selects a model artifact. A relative path resolves under the
project root. The shared CLI also accepts `--model`. When no model is explicitly
configured, the existing demo artifact is used if present; provenance reports a
null model identity when the lexical fallback operates without a model.

## Operator commands

```powershell
.venv\Scripts\python.exe -m aegisflow.cli analyse --input examples/drastha_mixed_evaluation_v3.jsonl --profile upload-demo --database output/drastha.db --report-output output/sprint8-evaluation.json
.venv\Scripts\python.exe -m aegisflow.cli analyse --input path/to/zeek-logs --profile deployment-baseline
.venv\Scripts\python.exe -m aegisflow.cli pcap --input capture.pcap --zeek-output output/capture-logs --all-threats --profile deployment-baseline
```

Without `--database`, the new analyse command returns a report without implicitly
persisting incidents. Existing `pcap` behaviour remains recon/DDoS unless
`--all-threats` is selected. Each log's input order is checked independently:
conn.log and ssl.log legitimately share UIDs, so separate log streams are not
treated as duplicate copies of the same record.

## Live/final semantics and storage

SSE `alert` notifications are explicitly provisional. Later evidence may merge
or retract them. Current resolved snapshots are stored by unique run ID in the
new additive `analysis_runs` table and can be read at
`GET /api/analysis-runs/{run_id}`. On completion, canonical findings and incidents
are imported into the existing analyst tables. This prevents obsolete provisional
alerts becoming permanent incidents. Other runs and analyst status are not deleted.

The completion message includes canonical `findings`, `incident_records`,
`quality`, `evaluation`, provenance, and a run ID. `emitted_alerts` counts
threshold notifications; `alerts` counts final findings. The UI reconciles these
and enables final incident investigation after completion. An interrupted stream
has no completed result; its stored running snapshot is provisional, not a clean
or completed analysis.

Alert provenance includes parser, DNS normalizer, engine and detector versions,
effective configuration, model version and SHA-256 identities for model,
configuration and trusted context. Hashes identify content; they are NOT digital
signatures or tamper-proof chain-of-custody evidence.

Schema creation is additive and idempotent for existing SQLite databases and the
shared PostgreSQL adapter. PostgreSQL deployment DDL includes analysis_runs.

## Verified results

- Full suite: **142 tests passed** (115 baseline + 27 new tests).
- Targeted session, Sprint 8 integration, mixed replay and ingestion: **43 passed**.
- Frontend: `pnpm run build` passed (TypeScript and Vite).
- Mixed replay: 452 accepted / 0 rejected / 0 timestamp regressions / 0 duplicate
  UIDs / 8 findings / 8 incidents / 8 TP / 0 FP / 0 FN / 86 TN / healthy.
- Simulation: 67 observations / 10 final findings / 8 incidents.
- Instant replay: 2 findings / 1 critical incident; rehearsal remains idempotent.
- Existing Starlette/httpx deprecation warning remains non-failing.

The HTTP parity test uses the real FastAPI upload route. SQLite restart/export
is exercised. PCAP orchestration is tested at the Zeek output boundary with a
mocked external conversion; existing runner tests verify subprocess commands.
This sprint did not rerun a real packet capture through an installed Zeek or a
live PostgreSQL server. No production throughput or accuracy claim is made.

## Explicit behavioural changes

- C2 no longer sees metadata from the future via a preloaded whole-file index.
  Its supporting confidence/evidence can therefore legitimately differ on other
  inputs, although existing fixture findings remain correct.
- DNS numeric query types now contribute their correct meaning instead of UNKNOWN.
- Partial connection/TLS normalization failures reject the complete record.
- CLI completed replays use shared finalization instead of raw threshold output.
- Instant replay merges its three sources chronologically; stage timing measures
  shared analysis time for each source group, not isolated detector CPU time.
- Live findings are provisional until reconciliation; final investigation is
  available at completion, while running snapshots are available by run ID.

## Work intentionally reserved for later sprints

Real packet-sequence extraction and deployment fingerprint prevalence (Sprint 9);
independent datasets and calibration (10–11); unbounded continuous ingestion,
backpressure and durable recovery/checkpoints (12); authentication, retention and
tamper-evident evidence (13); sustained load and actual capture-to-browser testing
(14); operational deployment (15). Replay preparation and result history still
use memory proportional to the finite replay; this is not a production streaming
queue. A crashed stream's running snapshot is not automatically resumed.

## Publication

Implementation is ready for publication with the confirmed codeWith-Ashwani
identity and its GitHub private email. The example.com placeholder is no longer
used for commits in this repository.
No author history was rewritten and no force push was performed.
