# Sprint 23 — pinned deployment boundary and confidence contract

## Outcome

Sprint 23 replaces an environment-only deployment assumption with a validated,
checksum-linked operator contract. Protected deployment can now select one
explicit configuration that defines the monitored network boundary, the exact
context policy and honest confidence semantics. Invalid, ambiguous or changed
configuration fails before detector execution.

This sprint does **not** claim production readiness or probability calibration.
It makes that limitation machine-readable and prevents heuristic detector scores
from being presented as attack probabilities.

## Deployment contract

`config/deployment_profile.json` is the checked-in staged-lab example. It defines:

- stable deployment ID;
- nonempty, canonical and non-overlapping internal CIDRs;
- a relative context-policy path plus SHA-256;
- `heuristic_evidence_score` confidence semantics;
- `not_probability_calibrated` calibration status;
- no production-approved DNS model;
- read-only ingest, no return path, no decryption and no active mitigation.

The example CIDRs are lab placeholders. Operators must create and review a
deployment-specific file for the actual enclave; the application never assumes
that all RFC1918 space belongs to the monitored organization.

The loader rejects path escape, absolute policy paths, invalid SHA values,
checksum mismatch, invalid CIDRs, overlapping boundaries, unsafe passive flags,
unsupported score claims and non-null DNS models. Sprint 21's failed DGA
candidate therefore cannot enter protected deployment through an implicit model
file or environment override.

## Runtime and preflight integration

Protected startup accepts:

```powershell
.venv\Scripts\python.exe scripts\operate.py preflight `
  --deployment-config config\deployment_profile.json `
  @OpsArgs
```

`serve` accepts the same option and passes only the verified file to the process.
`AnalysisSession.from_root` selects `deployment:<deployment_id>`, applies the
validated boundary and pinned context policy, and refuses simultaneous
`DRASTHA_INTERNAL_NETWORKS`. This ensures one authority for traffic direction.

Preflight returns the deployment/configuration digests, effective CIDRs, model
status and confidence status alongside the existing signed-store and TLS checks.
It still returns `production_ready: false` because a valid configuration is not
proof of operational accuracy, capacity or secure host deployment.

## Direction and confidence behaviour

Network scope deterministically classifies each connection as internal,
outbound, inbound or external. Exfiltration consumes a monitored-host-oriented
view only when the boundary proves which endpoint is internal.

Every standardized alert now exposes:

- `confidence`: detector evidence-strength score;
- `confidence_semantics: heuristic_evidence_score`;
- `confidence_calibration_status: not_probability_calibrated`;
- `confidence_is_probability: false`.

The same declaration is retained in analysis provenance and the report scope
note. Risk score and severity remain separate policy concepts.

## Reproduction

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sprint23_deployment.py
```

The audit is read-only. It verifies the pinned contract, policy checksum, all
four direction classes, selected deployment identity, confidence disclosure and
absence of a production DGA model. The checked-in result is
`output/sprint23_deployment_audit.json`.

## Remaining limits

- The staged CIDRs are examples, not the real critical-infrastructure topology.
- No detector has a deployment-representative probability calibrator yet.
- Confidence reliability must be measured on representative, separately held
  operational data before a calibrated-probability claim is possible.
- Remote service design, real certificate trust, host ACLs and production
  capacity remain outside this slice.
- Sprint 24 owns sustained mixed-protocol performance and reliability.

## Regression verification

- Targeted deployment/session/preflight suite: 49 tests passed.
- Full Python suite: 408 tests passed.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
- The existing Starlette/httpx deprecation and frontend HMR-port warnings remain
  visible; no warning, test or safety gate was disabled.
