# Sprint 15 — protected local operations and verified recovery

## Delivered slice

- Read-only signed SQLite verification and local deployment preflight.
- Create-only fresh-store initialization, online backup and separate-destination
  restore with authenticated manifest and independently selected expected head.
- Protected loopback HTTPS launcher: one worker, no reload, no trusted forwarded
  headers, no `--fresh`, deployment-baseline feature mode and explicit credentials.
- Real localhost HTTPS backup/restore drill, not just ASGI TestClient execution.
- Operational startup, monitoring, failure response, backup, restore, RPO/cutover
  and release/checkpoint rollback procedures in [the runbook](OPERATIONS_RUNBOOK.md).
- Expanded Git/Docker-context exclusions for operational secrets/backups.

No running service, firewall, certificate trust store, live database or user
credentials were changed. Existing hero/UI work remains outside this sprint.
The demo Docker/PostgreSQL path was not migrated into a protected production
deployment. Its broad `COPY output/` now excludes the designated backup/secret
directories, but operators must still keep all real data outside the build context.

## Implementation and guarantees

`src/aegisflow/operations.py` owns the operator-only workflow. It shares the exact
HMAC verifier with the repository instead of initializing/enrolling an existing
DB to check it. Auth-file parsing also has a pure explicit-file entry point.
Neither refactor changes detector thresholds, models, quality checks or existing
security semantics. Preflight additionally rejects unexpected DB schema objects.

`scripts/operate.py` exposes `init-store`, `verify`, `backup`, `restore`, `preflight`
and `serve`. Mutations require the respective explicit command. Backup includes
committed WAL via SQLite's backup API and verifies the resulting closed snapshot.
Restore never overwrites a live path or automatically cuts over. It authenticates
the fixed-scope manifest, checks selected head and verifies copied bytes/state.
No source file, journal or key is included in an analyst backup. The bundle is not
encrypted. Partial destinations are retained without success metadata; no broad
automatic cleanup is attempted. Limits are a 1 GiB snapshot and 30-second online
copy deadline (full verification is not a hard-time-bounded operation).

## Verification

- Full Python suite: **314 passed** (283 existing + 31 new operations tests).
- Separate operations/security/continuous/mixed selection: **83 passed**.
- Mixed append/restart/upload API parity: **452 accepted, 0 rejected, 8 findings,
  8 incidents, 8 TP, 0 FP, 0 FN, 86 TN, healthy**. Fixture hash remains
  `5848e73370f34e26583dd3678339e93b63b877c9ae3ed3a26b05d15952d844fd`.
- Frontend build and the four existing local theme tests pass; their uncommitted
  UI drafts are not included. The existing Starlette/httpx warning is non-failing.
- Final HTTPS drill: all nine gates pass; 25 accepted, one recon finding, healthy.
  Startup **2,075.18 ms**, online backup **12.22 ms**, restore **14.32 ms**, restored
  startup **2,059.01 ms**. This is a tiny synthetic timing observation, not RTO/SLA.
  See `output/sprint15_https_recovery_verified.json` and
  `output/sprint15_mixed_recovery_report.json`.

An intermediate drill failed readiness after larger preflight provenance filled
an unread Windows subprocess stdout pipe. The harness now sends child logs to a
disposable file; a regression writes beyond the anonymous-pipe buffer and checks
proper cleanup. The readiness deadline and TLS checks were not relaxed. The
failed attempt remains in `output/sprint15_https_recovery_final.json`; the initial
smaller-log pass remains in `output/sprint15_https_recovery_report.json`.

The real transport drill uses an ephemeral certificate with client hostname,
expiry and trust checks enabled. It contacts only localhost and tests missing
auth, role denial, upload/detection, evidence readback, an online backup while the
service runs, a later write, and exact selected-checkpoint recovery into a second
owned server. Its temporary secrets/capture-like inputs are not committed.

Unit tests cover read-only behavior, no unsigned enrollment, original bytes,
committed WAL, tampering, wrong keys, authentic-but-stale snapshots, missing heads,
manifest/path/sidecar issues, unexpected schema objects, no clobber, byte/deadline
budgets, expired roles, broken model/TLS configuration, public binding refusal,
secret placement and protected launcher flags.

## Explicit remaining production work

Local staged operations are delivered; general production deployment is not.
The preflight always reports `production_ready: false`. Host ACLs, disk encryption,
independent head storage, key custody, credential rotation, OS service supervision,
firewall/remote TLS architecture, PostgreSQL recovery and cross-store coordinated
recovery are still operator/research milestones. The runbook is not evidence that
those controls have been deployed.

Sprint 14's failed signed 1,000 records/sec run remains failed; capacity has not
been reclassified. Real Zeek and browser validation remain open. TLS **transport**
now has a localhost integration check, not a production certificate/deployment
certification. Failed DGA generalization, long-run state compaction/rotation and
multi-sensor recovery remain open. Engine changes intentionally invalidate old
continuous checkpoints; no checkpoint hash bypass or silent state reset was added.

Next priority: a separately tested scaling/checkpoint-migration design that keeps
the current integrity/recovery guarantees, followed by approved real-sensor and
operational-environment validation. The next sprint must not erase these gates.
