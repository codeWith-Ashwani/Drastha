# Sprint 22 — contextual false-positive hardening and Slow HTTP coverage

## Outcome

Sprint 22 closes the four explicit Sprint 20 lab gaps without deleting records,
reading ground truth during inference, weakening quality checks, or lowering an
existing detector threshold. The actual shared upload/analysis engine now
classifies the passive Slow HTTP connection-exhaustion shape, while a separate,
checksum-pinned operator policy suppresses the three approved operational
behaviours.

On the 13-capture, 392-record SIH-guided lab corpus:

| Evaluation | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Empty operator context | 9 | 3 | 0 | 2 | 75.00% | 100% | 85.71% | 60.00% |
| Pinned operator context | 9 | 0 | 0 | 5 | 100% | 100% | 100% | 0% |

These are unit-level results on a small deterministic lab corpus. They are not
production accuracy claims: the 95% Wilson upper bound for FPR remains wide
because there are only five benign units.

## Slow HTTP technical approach

The `ddos.behavioural` detector adds the specific subtype
`slow_http_connection_exhaustion`. It requires all of the following passive
metadata together:

- an observed HTTP service on a configured HTTP port;
- at least 20 matching flows beginning inside 15 seconds;
- partial/open Zeek connection state (`S1` or `OTH`);
- duration of at least 120 seconds per candidate;
- no more than 2,048 bytes and eight packets per candidate.

The evidence reports the long-lived partial connection count, estimated overlap,
minimum duration, maximum bytes and HTTP port. Because Zeek may emit a connection
record only when it ends, overlap is explicitly described as a start-time plus
duration estimate. The alert does not claim that a particular Slowloris tool was
observed and never inspects decrypted payload or HTTP headers.

Completed long HTTP sessions and partial but high-volume sessions are regression
controls and do not alert.

## Context safety model

Context is trusted operator configuration, never a field accepted from uploaded
telemetry. Periodic and bulk-transfer rules require exact source, destination,
port, protocol and optional service matches. Authorized scanner sources are an
explicit operator responsibility. Policy IP addresses are syntactically
validated before startup; invalid rules fail closed.

The isolated lab policy is stored in
`config/sih26145_lab_context_policy.json` and pinned in the audit by SHA-256
`222973548e6cebe123b5901b9333b91e731eb8e836a51949dd6240b22c154cf7`.
The audit records suppression counts per detector: eight health-check records,
three backup records and 22 scanner records. All nine malicious controls remain
detected. The same reviewed lab entries are also present in the normal demo
policy so uploading the corpus through the dashboard uses the expected context.

An incorrect or over-broad operator allowlist can hide attacks. Policy review,
expiry and deployment-specific change control therefore remain mandatory.

## Reproduction

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sprint22_hardening.py `
  --report-output output\sprint22_hardening_reproduction.json
```

The checker executes every capture twice through `analyse_prepared`: once with
empty context to preserve the counterfactual baseline and once with the pinned
policy. Every run uses a fresh session, so state and identity cannot leak between
scenarios.

## Boundaries and next work

- The corpus is deterministic synthetic metadata, not unseen production traffic.
- Exact endpoint policy proves the context mechanism, not automatic reputation.
- Slow HTTP needs real Zeek capture validation and deployment-specific long-poll
  baselines before production approval.
- Sprint 21's DGA candidate remains research-only and was not promoted.
- Sprint 23 owns deployment profile, network boundaries and confidence
  calibration.

## Regression verification

- Targeted detector/context/corpus suite: 17 tests passed.
- Full Python suite: 402 tests passed.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
- The existing Starlette/httpx deprecation and frontend HMR-port warnings remain
  visible; no warning, test or quality gate was suppressed.
