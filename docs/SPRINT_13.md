# Sprint 13 — protected analyst access and signed evidence

Delivered: 4 September 2026. This sprint adds an **opt-in, SQLite-backed security
slice**: expiring opaque credentials and roles, HTTPS enforcement, authenticated
review identity, HMAC audit/evidence verification, signed export receipts and
administrator-controlled retention of completed analysis reports.

No detector, threshold, model, input fixture or existing web design changed.
The existing installation remains in explicitly labelled `local-demo` mode.
**Security has not been enabled on the user's current database or running server.**
No real evidence was deleted, no production credentials were issued, and no TLS
certificate or security claim for the live installation was created.

## Access boundary

`DRASTHA_AUTH_MODE=required` requires a valid `DRASTHA_AUTH_FILE` and a signed
SQLite repository with an external `DRASTHA_AUDIT_KEY_FILE`. Missing or invalid
configuration fails startup. An existing unsigned store cannot silently become
certified evidence: bootstrap a fresh signed store and import reviewed originals.
Opening a signed store through the ordinary unsigned repository is refused.
PostgreSQL signed/protected mode is not implemented and fails explicitly; existing
unsigned PostgreSQL functionality is not replaced.

All HTTP routes, including static dashboard content, docs, health, sample downloads,
exports and streams require authentication in protected mode. Only actual CORS
preflight requests bypass credentials, and those cannot execute application routes.
Unknown origins are not granted CORS permission. WebSockets are denied in protected
mode until an authenticated WebSocket design exists.

| Role | Permitted actions |
|---|---|
| viewer | Read health, incidents, evidence, reports, samples and exports |
| analyst | Viewer access plus replay analysis, demo/simulation, status and feedback |
| admin | Analyst access plus audit verification, retention preview/apply and holds |

The existing simulation endpoint uses GET but creates findings; it is explicitly
classified as a mutation. A viewer cannot start it. Feedback's submitted `analyst`
field is ignored in protected mode; the authenticated principal is stored instead.
Audit context records the principal and route/operation for repository changes.

Credentials are random 256-bit opaque tokens, not user-chosen passwords. The server
configuration contains SHA-256 token digests, role, principal and expiry. Bearer
headers support API clients; HTTP Basic uses the principal as username and the same
opaque token as password for the browser's native authentication prompt. There is
no token in a URL, browser storage, cookie or custom JWT. Digest comparisons use
constant-time comparison primitives; see the
[FastAPI Basic authentication guidance](https://fastapi.tiangolo.com/advanced/security/http-basic-auth/).

HTTPS is mandatory, including loopback protected-mode requests. The middleware
does not trust `X-Forwarded-Proto` itself; ASGI servers/proxies can alter the scheme,
so configure those trust boundaries explicitly. Prefer direct TLS with
`--no-proxy-headers` until a trusted reverse proxy has been reviewed. Basic
credentials are browser-ambient: mutations require an exact configured HTTPS
Origin, or the browser's same-origin Fetch Metadata signal when Origin is absent.
Cross-site/absent-origin Basic API writes are denied. Bearer clients set the header
explicitly and do not use ambient browser authentication. Protected responses add
no-store, nosniff, no-referrer and frame-denial headers.

Credentials are loaded at startup. Expiry is checked at request start; in-flight
requests/SSE are not cancelled at token expiry. To revoke or replace credentials,
update the protected config and restart every worker. Basic authentication has
browser-managed caching, not a reliable application logout/session mechanism.
SSO, MFA, user provisioning, password login, refresh/session management, rate
limiting and auth-failure audit forwarding remain future work. Do not treat this
as a complete identity-management system or expose demo mode to untrusted clients.

## Tamper evidence and exports

`AuditedIncidentRepository` wraps the existing repository transactions. Under a
SQLite write reservation it verifies the full HMAC chain and a deterministic
digest of current protected rows before allowing reads/writes. It then commits
any data changes and their signed audit event together. A signing failure rolls
both back. No-op writes do not create redundant state-change entries. All existing
import, feedback, status, report and runtime-state methods use this wrapper, so
Sprint 12 projection/recovery inherits verification without bypassing the journal.

Protected tables: incidents, alerts, analyst feedback, analysis runs, runtime state
and retention metadata. Events contain sequence, previous MAC, actor, operation,
timestamp, before/after row digests and complete-state digest. Raw tokens, notes and
traffic payloads are not duplicated into audit entries. Export receipts bind the
exact canonical export content digest and audit verification information to an
HMAC; modifying the returned content invalidates the receipt. HMAC follows
[Python's HMAC primitives](https://docs.python.org/3/library/hmac.html), not a custom
cryptographic algorithm. This is **symmetric authentication**, not a public-key
signature or non-repudiation claim; anyone holding the audit key can forge receipts.

`GET /api/security/audit` verifies the chain/current state and returns its head.
Retain that head independently and compare it with `verify_evidence(expected_head)`
when exact-checkpoint verification is needed. New legitimate entries also change
the head. Database-only checks cannot distinguish an authentic old full backup from
the latest state. A regression test intentionally demonstrates that removing a
read-only tail event is detected by an independent head, not by an unanchored
database check. External anchoring/WORM storage is **not automated** in this sprint.

DB-only row modification/insertion, inconsistent deletion, chain edits and wrong
keys fail verification; API evidence access returns 503. Key theft, host compromise,
coordinated replacement of all state/keys/anchors, secure clock attestation, backup
custody and sector-specific forensic admissibility remain outside this slice.
HMAC does not encrypt stored evidence or securely erase deleted bytes.

## Retention is intentionally conservative

Only completed analysis-run reports are eligible. Age comes from trusted local
storage time, not a timestamp supplied in traffic or JSON. Updated reports refresh
their storage age; unchanged idempotent writes do not. A separately stored hold
prevents deletion. Active/failed continuous-stream reports remain excluded.

1. An admin requests `GET /api/security/retention?before=<past Unix seconds>`.
2. The dry-run returns up to 500 eligible run IDs, scope, signed head and plan hash.
3. The admin submits the same cutoff/hash to `POST /api/security/retention`.
4. Under the same database transaction lock, the server recomputes the plan. A
   changed report, hold or ledger head produces 409, requiring a new preview.
5. Report/retention rows and the signed deletion event commit atomically.

`PUT /api/security/retention/holds/{run_id}` accepts `{"held": true}` or false and
is also admin-only/audited. Retention endpoints are disabled in local demo mode,
even if a signed repository is supplied. No scheduled purge is enabled.

Incidents, alerts, feedback, detector state, raw source files, continuous journals
and the audit chain are never removed by this operation. Incident copies may still
retain evidence from deleted reports: this is **report-retention groundwork**, not
a privacy erasure or total-disk retention policy. Application deletion requires a
separately retained backup for recovery; SQLite pages/backups may retain bytes.
Full evidence lifecycle/retention and journal compaction remain open.

## Operator setup for a fresh deployment

Install the existing API dependencies. Choose a new owner-only directory outside
the repository and an exact HTTPS dashboard origin:

```powershell
.venv\Scripts\python.exe scripts/init_security.py --directory C:\DrasthaSecrets\fresh-deployment --origin https://localhost:8443
```

The create-only helper generates `auth.json`, a separate 32-byte `audit.key`, and
`bootstrap-tokens.json` for private distribution. It prints only paths/expiry, never
tokens. Default expiry is 24 hours; configurable range is five minutes to 30 days.
The initial principals are viewer, analyst and admin; replace them with individually
assigned identities for actual operations. On Windows, first ensure owner-only
inherited ACLs; POSIX creation modes are not a Windows ACL guarantee. Store the key
separately from database/backups. Do not regenerate/change the audit key for an
existing signed database when rotating login credentials.

Configure the new service process (example paths, not changes made by this sprint):

```powershell
$env:DRASTHA_AUTH_MODE = 'required'
$env:DRASTHA_AUTH_FILE = 'C:\DrasthaSecrets\fresh-deployment\auth.json'
$env:DRASTHA_AUDIT_KEY_FILE = 'C:\DrasthaSecrets\fresh-deployment\audit.key'
$env:DRASTHA_DB = 'output/drastha-protected.db'
.venv\Scripts\python.exe -m uvicorn aegisflow.api:create_app --factory --host 127.0.0.1 --port 8443 --no-proxy-headers --ssl-keyfile C:\DrasthaSecrets\tls.key --ssl-certfile C:\DrasthaSecrets\tls.crt
```

Supply an independently provisioned, trusted TLS certificate/key. The helper does
not generate TLS certificates, change OS ACLs, enable security or migrate data.
An existing production database must not be renamed, cleared or re-signed merely
to pass the bootstrap check. Plan evidence migration/backup separately.

## Verification and remaining boundaries

```powershell
.venv\Scripts\python.exe -m unittest tests.test_security_sprint13 tests.test_continuous_ingestion tests.test_mixed_evaluation_replay -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

- Full suite: **267 passed** (240 prior + 27 new security tests).
- Protected actual HTTP upload: 452 accepted, 8 findings/8 incidents, 8 TP, 0 FP,
  0 FN, 86 TN, healthy quality; no threshold/model/quality-check changes.
- Protected SSE and signed-store continuous checkpoint/recovery pass; exports,
  fake analyst identity, HTTP/expired/missing credentials, role restrictions,
  CSRF, malicious origins, tampered DB/export, rollback and retention are covered.
- Frontend build and four existing theme tests passed; no browser/TLS-deployment
  validation, real PostgreSQL validation or penetration test was performed.
- Full ledger/state scans and serialized SQLite transactions prioritize a small
  inspectable prototype. They are not a scalable audit service. Sustained-load
  measurement and optimization belong to Sprint 14.
- Sprint 11 calibration, Sprint 12 compaction/rotation, external audit anchoring,
  credential lifecycle, database encryption and complete evidence retention remain
  explicit production work. The next numbered sprint does not erase these gaps.
