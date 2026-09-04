# Protected local operations runbook

Scope: a **staged, loopback-only signed SQLite analyst service** in the monitoring
enclave. This is not an Internet-facing deployment recipe, a Windows/Linux service
installation, a Zeek installer, or a production-readiness certification. The
existing Docker/PostgreSQL composition and `start-demo.ps1` remain demo paths.
Never run `demo-serve --fresh` against operational data.

## 1. Release and safety gates

Before installation or upgrade, an operator must approve the release commit,
dependencies, model/policy hashes, security configuration, network boundary and
rollback point. Run the full test suite and mixed-fixture check from that exact
release. Do not infer live accuracy from synthetic evaluation.

- Keep the protected-network mirror/data-diode input read-only. No health probe,
  handshake, DNS lookup or mitigation command may cross that ingest boundary.
- Select explicit `DRASTHA_INTERNAL_NETWORKS` for directional/exfiltration analysis.
  Review the effective model and context policy in preflight provenance. The
  default demo DGA model is not a production-calibrated model.
- Sprint 14 measured only a bounded 100 conn-records/sec workload. Signed 1,000
  records/sec failed; do not deploy against that load on the basis of old demo
  throughput numbers. Real Zeek/all-protocol capacity remain unverified.
- Provision owner-only storage, sufficient free disk and separately controlled
  keys. On Windows, review inherited NTFS ACLs; POSIX `0700`/`0600` requests do not
  establish Windows ACL protection. Do not store security files in the served
  dashboard directory, repository, container image or backup bundle.
- Obtain an operator-approved TLS certificate with the intended hostname/SAN and
  chain. Confirm client hostname, expiry and trust validation. Preflight loads
  the key pair but does not certify the certificate's trust chain or validity.
- Define who owns credential rotation, backup retention, incident escalation and
  restore approval. There is no automatic SSO/MFA/revocation lifecycle here.

## 2. New signed store and preflight

Example paths below are placeholders outside the repository. The operator first
creates/restricts the parent directory `D:\DrasthaOps` and provisions TLS files.
Existing directories/data must **not** be removed to make these commands pass.

```powershell
.venv\Scripts\python.exe scripts/init_security.py --directory D:\DrasthaOps\security --origin https://localhost:8443
.venv\Scripts\python.exe scripts/operate.py init-store --directory D:\DrasthaOps\store-v1 --audit-key D:\DrasthaOps\security\audit.key

$OpsArgs = @(
  '--database', 'D:\DrasthaOps\store-v1\analyst.db',
  '--audit-key', 'D:\DrasthaOps\security\audit.key',
  '--auth', 'D:\DrasthaOps\security\auth.json',
  '--cert', 'D:\DrasthaOps\tls\server.crt',
  '--tls-key', 'D:\DrasthaOps\tls\server.key',
  '--web', 'F:\Drastha\Drastha\web\dist',
  '--root', 'F:\Drastha\Drastha',
  '--host', '127.0.0.1', '--port', '8443'
)
.venv\Scripts\python.exe scripts/operate.py preflight @OpsArgs
```

Bootstrap creates fresh random tokens and an audit key; it does not enable the
service, migrate existing unsigned evidence or distribute credentials. The token
file is sensitive. Distribute it privately and handle its retention according to
the operator's secret-custody policy. Default bootstrap tokens expire in 24 hours.

Preflight opens the existing database with SQLite `mode=ro` and a consistent read
transaction. It checks SQLite integrity, the expected table set, absence of
unexpected triggers/views, every HMAC link and the signed current row state. It
does not create schema, enroll unsigned data, append an audit entry, reset state
or mutate analyst content. SQLite's normal WAL locking/sidecar handling still
applies; do not copy an active DB by ignoring its WAL.

It also validates distinct configuration files, the built dashboard/root, all
three unexpired roles, a matching loopback HTTPS origin/port, TLS key-pair loading
and the configured model/policy. It explicitly returns `production_ready: false`.
Treat a failed check as a stop condition; do not suppress it.

## 3. Explicit local startup and readiness

```powershell
.venv\Scripts\python.exe scripts/operate.py serve @OpsArgs
```

Only `serve` enables protected settings, scoped to its own process. It repeats
preflight, binds loopback, selects the derived deployment-baseline profile, starts
one Uvicorn worker, disables reload/proxy-header trust, and requires direct TLS.
It never resets or replaces the database. Background supervision, remote access,
reverse proxy trust and TLS termination need a separately approved deployment
design; do not substitute `0.0.0.0`, bypass HTTPS or trust arbitrary forwarded
headers to get past these controls.

Use a trusted HTTPS client to check `/api/health` with a valid viewer credential.
Expected checks: no credential -> 401; viewer mutation -> 403; expired token ->
401; authenticated GET -> 200. Do not put tokens in URLs, shell history or public
logs. Check both incident detail and analysis-run readback, not health alone.
Health is service/evidence readiness, **not proof that the sensor is receiving
fresh traffic**. A browser using Basic credentials still needs separately approved
browser validation; this sprint's transport drill is a programmatic TLS client.

## 4. Normal monitoring and failure response

| Signal | Operator response |
|---|---|
| No fresh source bytes or advancing stream offset | Check the enclave-side sensor/exporter and local file permissions. Never probe the production source. |
| Growing backlog or long API visibility | Record offered rate, offsets, disk/CPU/RSS and queue limits. Escalate overload; never discard input or weaken audit checks. |
| `awaiting_partial_line` | Confirm exporter is still writing. Do not truncate its line or force checkpoint advancement. |
| `capacity_reached` / worker exit 2 | Stop automatic restart loops; preserve input and journal. Compaction/rotation handoff is not implemented. |
| Rejected/late/duplicate records or degraded quality | Inspect quarantined reasons and original ordering. Keep original bytes; correct the producer/fixture, not the quality flag. |
| Evidence-integrity failure / API 503 | Stop writes, preserve DB plus sidecars and relevant logs, notify the evidence owner. Never re-sign or initialize over the damaged store. |
| Auth 401/403 or TLS failure | Check expiry, role, exact origin and certificate trust. Never switch to local-demo or disable TLS verification as a workaround. |
| Disk full or backup timeout | Preserve source/checkpoint and partial backup; free capacity through an approved retention/recovery action, not broad deletion. |

Keep liveness/readiness credentials and log access restricted. Define alerts in
the site's approved monitoring system; this sprint does not install a scheduled
monitor, service manager or unattended restart policy.

## 5. Online analyst-store backup

```powershell
.venv\Scripts\python.exe scripts/operate.py backup --database D:\DrasthaOps\store-v1\analyst.db --audit-key D:\DrasthaOps\security\audit.key --destination D:\DrasthaOps\backup-001
```

The destination must be new and its parent must already exist. The tool uses
SQLite's online backup API, including committed WAL transactions, rather than a
raw copy of a live `.db`. It closes the snapshot into standalone DELETE-journal
mode, verifies it using the external key, hashes its bytes and writes a signed
manifest last. The 30-second copy deadline and 1 GiB snapshot cap are explicit
operator-tool limits; verification is a full scan and not a hard real-time bound.

Bundle contents:

- `analyst.db`: incidents, alerts, feedback, analysis reports, runtime state,
  retention holds/metadata and the evidence audit chain.
- `manifest.json`: HMAC-authenticated scope, size, checksum, row inventory and
  selected evidence head. Its presence alone is not sufficient: verify it.
- `head.json`: copy this to independently controlled storage and record approval
  of the restore point. A copy beside the DB is **not** independent anchoring.

No audit key, credentials, certificate, sensor file, stream journal, model or code
is included. The backup is **not encrypted**. Manage filesystem ACLs/encryption,
offsite copying, retention and key escrow through approved operator controls.
All sources remain unchanged by the backup operation; concurrent application
writes can continue after the captured point.

Failures leave an incomplete directory for diagnosis. Without successful
verification and a completed manifest it must not be used. The tool never erases
or overwrites it; choose a new destination after correcting the fault. File fsync
and SQLite consistency do not replace tested storage, offsite durability or
power-loss validation.

## 6. Restore drill and manual cutover

```powershell
.venv\Scripts\python.exe scripts/operate.py restore --bundle D:\DrasthaOps\backup-001 --audit-key D:\DrasthaOps\security\audit.key --expected-head E:\EvidenceAnchors\backup-001-head.json --destination D:\DrasthaOps\restored-001
.venv\Scripts\python.exe scripts/operate.py verify --database D:\DrasthaOps\restored-001\analyst.db --audit-key D:\DrasthaOps\security\audit.key --expected-head E:\EvidenceAnchors\backup-001-head.json
```

The expected head must come from the operator-approved independently retained
checkpoint, not be automatically read from an untrusted bundle. An old valid
backup fails when the expected head is newer. Intentionally selecting the older
head is an explicit restore-point decision with an associated data-loss window.

Restore verifies the manifest HMAC, exact fixed filename/scope, selected head,
copied byte size/hash, SQLite integrity, all signed rows and row inventory. It
rejects bundle symlinks/sidecars, nested destinations and existing destinations.
The informational restore receipt appears only after successful verification.
A failed destination must not be started merely because `analyst.db` exists.

There is **no automatic live replacement or cutover**. With owner approval:

1. Stop the analyst API and continuous worker gracefully; preserve the prior DB,
   source, journal and sidecars. Record the last acknowledged offsets/head.
2. Run verification and preflight against the new restored path. Validate required
   reports, incident details, feedback and retention holds in an isolated service.
3. Approve the recovery point/RPO: writes newer than the backup are absent. Do not
   quietly replay a journal into the restored analyst store; that can republish
   newer detections without restoring intervening analyst reviews.
4. Point the approved launcher at the restored DB only after that reconciliation.
   Keep the old installation intact as the rollback candidate.

This is analyst-store recovery, **not an atomic backup of sensor + journal +
analyst DB**. For bounded coordinated journal/analyst recovery, use section 8;
source disaster recovery and rotation remain unsupported. The continuous checkpoint
pins the complete engine digest: a source-code upgrade changes that contract.
Never edit the digest, delete a checkpoint or reset detector state to force resume.
Use the previous exact release/source/model/policy/limits for an approved rollback,
or design/test an explicit migration before upgrading a nonempty checkpoint.

## 7. Repeatable disposable acceptance drill

```powershell
.venv\Scripts\python.exe scripts/check_operational_recovery.py --report-output output/ops-drill-new.json
.venv\Scripts\python.exe -m unittest tests.test_operations_sprint15 -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

OpenSSL must already be installed for the disposable drill; absent OpenSSL is
reported as blocked, not passed. The drill creates a short-lived localhost test
certificate and trusts it only in its own verifying client. It starts/stops owned
temporary servers, exercises a 25-record scan through real HTTPS, backs up online,
makes a later status change, restores the deliberately selected earlier head and
checks exact report/evidence readback. It does not change the OS trust store,
firewall, running deployment, browser or monitored network. Temporary synthetic
data and test secrets are removed when the drill ends; only the non-secret result
report is retained. Measured milliseconds are a tiny-fixture observation, not a
production RTO or SLA.

## 8. Coordinated stream recovery (Sprint 17)

This is a separate operator workflow for **one existing continuous journal and
its signed analyst store, using the identical engine/model/profile/policy**.
It is not a cross-version migration or a replacement for the online analyst-only
backup above. Do not run a new engine against an old nonempty checkpoint merely
to create its backup: use the exact original release. Never rewrite engine hashes.

Prerequisites: approve the recovery point, protect the output and anchor storage,
stop the continuous worker and pause analyst writes. All workers sharing the
analyst store should be stopped. Preserve the original sensor file at its original
path and filesystem identity, including its complete committed prefix. The local
producer may append a tail, but must not rewrite, truncate, relocate or rotate the
file. No command here contacts the protected network or writes to the input.

The new recovery tool must already be present in the release that created the
checkpoint. Adding this module changes the engine digest: existing Sprint 16
checkpoints are not automatically compatible with Sprint 17. Retain the prior
release for rollback; migrating those checkpoints is still separate work.

Example paths are placeholders; parents and independently controlled anchor
storage must already exist. Use the profile, root, model override (if any), and
environment configuration that originally created the stream. `upload-demo`
below reproduces the synthetic drill; operational streams generally use the
default `deployment-baseline`, not demo thresholds.

```powershell
$RecoveryArgs = @(
  '--source', 'D:\DrasthaOps\sensor\conn.jsonl',
  '--audit-key', 'D:\DrasthaOps\security\audit.key',
  '--root', 'F:\Drastha\Drastha',
  '--profile', 'upload-demo'
)
.venv\Scripts\python.exe scripts/operate.py stream-backup @RecoveryArgs --journal D:\DrasthaOps\stream\journal.db --database D:\DrasthaOps\store-v1\analyst.db --destination D:\DrasthaOps\cut-001
```

Backup acquires the existing worker lock and both SQLite writer locks, snapshots
committed WAL content, verifies the full signed analyst store, and reconstructs
the journal on a disposable copy without advancing input or publishing findings.
It requires exact report/evidence agreement between the journal and analyst store.
A stale projection must first be reconciled using the original worker/release;
the tool refuses rather than silently repairing or re-signing it.

The new bundle contains `journal.db`, `analyst.db`, `anchor.json` and an
HMAC-authenticated `manifest.json` written last. **The journal includes raw traffic;
the bundle is not encrypted.** Protect it as sensitive evidence and never commit
it. Keys, credentials, code, models and the source file are excluded. Retain the
exact release/dependencies/models and signing key through separate approved
custody procedures. A bundle alone cannot recover a lost source file or key.

Copy `anchor.json` to independently controlled storage through your approved
procedure and record the chosen recovery point. Passing a copy from inside the
bundle satisfies the CLI argument but does not provide independent rollback
protection; the tool cannot certify your storage custody.

```powershell
.venv\Scripts\python.exe scripts/operate.py stream-check @RecoveryArgs --bundle D:\DrasthaOps\cut-001 --expected-anchor E:\EvidenceAnchors\cut-001-anchor.json
.venv\Scripts\python.exe scripts/operate.py stream-restore @RecoveryArgs --bundle D:\DrasthaOps\cut-001 --expected-anchor E:\EvidenceAnchors\cut-001-anchor.json --destination D:\DrasthaOps\recovered-stream-001
```

`stream-check` rehearses restoration on temporary copies and reports compatibility,
not production readiness. `stream-restore` requires a new separate directory,
validates the manifest/independent anchor, byte hashes, signed head, source prefix,
engine/provenance and reconstructed results. It leaves a completion receipt only
after verification. The receipt is informational, not a signed migration receipt.
Failures retain incomplete restore output; never start it or overwrite it to retry.
Choose a new destination after investigating the failure. Check exit code 0 and
successful verification, not just the presence of database files.

The selected cut preserves status, feedback and retention holds, but excludes
later analyst changes. With operator approval, inspect the restored API/report,
reconcile the recovery-point data-loss window, and manually configure **both**
the restored journal and restored analyst DB together using the original source
and exact engine. Stop old writers before cutover. Never run old and restored
workers simultaneously: they have distinct lock files. No launcher/configuration
is changed by these tools. Keep originals intact for rollback.

Limits: 20,000 committed lines and 64 MiB raw committed source bytes; 1 GiB per
database snapshot with a 30-second SQLite snapshot-copy budget. Full verification
and reconstruction have no hard end-to-end time guarantee. No state compaction,
live rotation, cross-version transformation, source rebinding, cross-database
exactly-once delivery, offsite durability or power-loss guarantee is introduced.

Disposable acceptance commands (use a new report filename):

```powershell
.venv\Scripts\python.exe scripts/check_stream_recovery.py --report-output output/stream-recovery-drill-new.json
.venv\Scripts\python.exe -m unittest tests.test_stream_recovery_sprint17 tests.test_mixed_evaluation_replay -v
```

The drill uses isolated synthetic files and authenticated in-process ASGI upload
and readback. It does not exercise browser/TCP/TLS transport or modify a running
service. See [Sprint 17](SPRINT_17.md) for measured results and remaining limits.
