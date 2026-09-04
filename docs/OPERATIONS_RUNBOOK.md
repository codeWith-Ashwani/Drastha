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
analyst DB**. Coordinated worker recovery, rotation, source identity and duplicate
projection semantics require separate review. The existing continuous checkpoint
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
