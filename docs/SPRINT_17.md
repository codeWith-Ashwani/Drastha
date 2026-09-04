# Sprint 17 — coordinated same-engine stream recovery

## Delivered scope

Operator-only, bounded recovery of one continuous-ingestion journal together
with its signed SQLite analyst store. The selected recovery point preserves
detection evidence, incident review status, feedback and retention holds. Input
remains read-only. No detectors, thresholds, models, alert schema or evaluation
fixtures changed. No running service was reset or cut over during verification.

This is **same-engine recovery**, not cross-version checkpoint migration, source
disaster recovery, an unattended service or production-readiness certification.

## Implementation

- `src/aegisflow/stream_recovery.py`: acquire the existing worker lock and both
  SQLite writer locks; snapshot journal and analyst DB including committed WAL;
  verify the signed store and reconstruct journal state on disposable copies.
  Require exact journal/report/projected-evidence agreement before publishing
  an HMAC-authenticated manifest. Never silently repair stale analyst projection.
- `scripts/operate.py`: expose `stream-backup`, `stream-check`, `stream-restore`.
  Require an explicit source/key/profile and, for check/restore, expected anchor.
  Default profile remains deployment-baseline. Invalid operations return exit 2.
- Restore authenticates the manifest and independently retained anchor, checks
  copied sizes/hashes and selected audit head, verifies original source identity
  and committed-prefix digest, and reconstructs detection state. Only a new
  destination is allowed. The informational completion receipt is written after
  validation, not used as a substitute for it. Partial failed outputs are retained.
- Compatibility check runs the same restore logic on temporary copies. Engine
  or profile/model/policy mismatch fails closed; no digest rewrite or fallback.
- `scripts/check_stream_recovery.py`: reproducible signed mixed-fixture drill
  through continuous recovery, authenticated API readback and the actual
  `/api/replays/analyse` upload-analysis path. Counts, quality and behaviour-level
  confusion matrices are asserted independently for continuous and upload paths.
- `tests/test_stream_recovery_sprint17.py`: 28 new regression tests.
- `.gitignore`: exclude `output/stream-recovery/` bundles, which contain raw
  traffic. Other operator destinations must also stay outside source control.
- README, roadmap and [operations runbook section 8](OPERATIONS_RUNBOOK.md#8-coordinated-stream-recovery-sprint-17)
  explain prerequisites, commands, anchor custody, failure handling and cutover.

## Recovery contract and limits

1. Stop the worker and pause analyst writes; shared-store writers should all be
   stopped. The tool verifies/locks a cut, not a live distributed transaction.
2. Keep the original source path, filesystem identity and committed prefix.
   Appended bytes may remain after the cut; source replacement, truncation and
   relocation fail. Raw journal records do not authorize source rebinding.
3. Retain the signing key and exact engine/dependencies/model/profile/policy
   separately. The bundle excludes source files, keys, credentials, code/models.
   It contains raw journal traffic and is **not encrypted**. Filesystem ACLs,
   encrypted/offsite storage and secret custody are operator responsibilities.
4. Keep the checkpoint anchor independently; a copy beside the bundle does not
   prevent rollback to another authentic backup. CLI cannot certify independence.
5. The selected cut excludes later analyst reviews. No automatic merge or cutover
   occurs. Approve the recovery point and reconcile later changes before pointing
   both worker journal and analyst service at the restored pair. Keep originals.
   Never run old and restored workers simultaneously against the shared source.
6. Bounded at 20,000 committed lines / 64 MiB raw committed bytes. Each database
   snapshot is capped at 1 GiB with a 30-second SQLite copy budget. Reconstruction
   and full integrity verification have no hard end-to-end latency guarantee.
7. Delivery remains idempotent at-least-once across two stores, not cross-database
   exactly-once. No compaction, rotation, power-loss/offsite durability guarantee,
   multi-sensor coordination or general capacity improvement is claimed.

Adding a Python module changes the complete engine digest. **Sprint 16 journals
cannot automatically resume on Sprint 17**, even though detector logic is unchanged.
The recovery tools must be present in the engine release that created the cut.
Retain the original release for existing checkpoints; migration still needs an
explicit old/new-engine equivalence protocol. Do not edit hashes or clear state.

## Regression coverage

Tests cover exact selected review/feedback/hold recovery and append continuation;
active worker/analyst writer refusal; stale projection; input-preserving rehearsal;
engine/profile/key/anchor mismatch; manifest and both snapshot-file tampering;
unexpected WAL sidecars; changed/truncated/rebound source; corrupted dispositions,
quality snapshots and journal triggers; tampered analyst rows; create-only paths;
partial copy/disk failure; committed WAL; rejected/ignored lines; CLI entry points;
actual mixed upload/API parity; missing locks; source/database/sidecar aliases;
snapshot budget failure; and abrupt child-process exit followed by safe retry.

## Acceptance results — 4 September 2026

Final full Python suite: **362 tests passed in 27.979 seconds**. Separate Sprint 17
and mixed-replay suite: **29 tests passed in 7.659 seconds**. The existing
Starlette TestClient/httpx deprecation warning remains; it is not a failed test
and no dependency change is included in this recovery sprint.

The final disposable drill is retained at
`output/sprint17_delivery_recovery.json`. Both continuous and actual upload paths:

| Check | Result |
|---|---:|
| Accepted / rejected records | 452 / 0 |
| Findings / incidents | 8 / 8 |
| TP / FP / FN / TN | 8 / 0 / 0 / 86 |
| Behaviour-level precision / recall / F1 | 100% / 100% / 100% |
| Behaviour-level FPR | 0% |
| Out-of-order records / duplicate UIDs | 0 / 0 |
| Data quality | healthy |

All nine recovery gates passed, including authenticated exact API readback,
selected-head equality, source/journal/analyst preservation by backup, preserved
reviews/feedback/holds, and no silent merge of later reviews. Restart reconstructs
452 records. One deliberately appended benign record in a disposable source copy
produces 453 accepted and still 8 findings, with healthy quality. The original
452-record fixture is unchanged.

This measures scenario/endpoint behaviour units on a synthetic fixture, not
production/generalization accuracy. Ground-truth fields are scored only after
inference; no detector state reset or metric tuning uses those fields. The existing
identity-overlap disclosure remains in both reports.

Single-run measurements: backup **141.792 ms**, restore **126.870 ms**, reconstruct
and append **112.257 ms**. These are small-fixture observations, not a production
RTO or SLA. API checks use ASGI TestClient with authentication, not browser, TCP
or TLS transport. Sprint 15's HTTPS work remains separate evidence.

The earlier `output/sprint17_coordinated_recovery.json` development report and
`output/sprint17_coordinated_recovery_final.json` pre-pause report are retained as
historical measurements; the delivery report adds explicit upload-path counters
and scoring assertions. Reports pin their actual engine digest. Delivery engine:
`00cb6077ca2e48729a3d55f7320ecb67af61e9b043cd5a056d6340b4096d5c4d`.

## Reproduce

Use a fresh process and a new report filename:

```powershell
.venv\Scripts\python.exe scripts/check_stream_recovery.py --report-output output/sprint17-drill-new.json
.venv\Scripts\python.exe -m unittest tests.test_stream_recovery_sprint17 tests.test_mixed_evaluation_replay -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

No production databases, credentials or traffic are committed. Pre-existing
frontend/logo/maze edits are preserved separately and excluded from this sprint
commit. Remaining work includes explicit version migration, source disaster
recovery/rotation, supervision and remote deployment, real-sensor validation and
model generalization. The failed 1,000-records/sec gates remain failed; this sprint
does not modify or re-label capacity evidence.
