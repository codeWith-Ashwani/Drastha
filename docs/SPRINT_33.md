# Sprint 33 — final SIH submission release

## Outcome

Sprint 33 freezes the SIH problem-statement prototype as `drastha-sih-v1.0`.
The v2 release manifest checksum-pins the final input-compliance, threat,
quality, contextual false-positive, sensor, performance and deployment evidence.
The checker does not trust the retained reports alone: it reruns the current
Sprint 32 HTTP-upload acceptance and compares the measured results with every
published release claim.

The release remains deliberately labelled **submission demo ready**, not
production ready. Confidence is an explainable heuristic evidence score rather
than a calibrated attack probability. Collector-decoded flow records are
supported, while raw binary NetFlow/IPFIX/sFlow datagrams, a physical data diode,
general QUIC interoperability and production accuracy are not claimed.

## Final measured acceptance

- Chronological mixed replay: 452 accepted, 0 rejected, 8 findings, 8 incidents,
  8 TP, 0 FP, 0 FN, 86 TN and healthy quality.
- Identity-separated corroboration: 153 accepted, 0 rejected, 8 findings,
  8 incidents, 8 TP, 0 FP, 0 FN, 107 TN and healthy quality.
- SIH lab corpus after contextual policy: 9 TP, 0 FP, 0 FN and 5 TN.
- Sustained shared-path target: 50 records/second for 60 seconds.
- The final acceptance also checks passive/read-only operation, no payload
  decryption, alert/incident evidence, SQLite saved runs, SIEM export and SSE.

These are controlled, reproducible prototype measurements and must not be
presented as real-world production accuracy.

## Reproduction

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sprint33_release.py `
  --report-output output\sprint33_release_audit.json

.venv\Scripts\python.exe -m unittest discover -s tests -v

Set-Location web
node --test tests/replay-evidence.test.mjs tests/theme.test.mjs tests/topology.test.mjs
npm run build
Set-Location ..
```

For the final prepared-host ZIP, commit the exact candidate first and run the
deterministic Sprint 26 bundle checker. The ZIP excludes credentials, databases,
packet captures, runtimes and dependencies. Rehearsal therefore requires a host
with the documented Python packages already installed.

```powershell
.venv\Scripts\python.exe scripts\check_sprint26_bundle.py `
  --release-checker scripts/check_sprint33_release.py `
  --bundle-output build\drastha-sih-v1.0.zip `
  --report-output output\sprint33_bundle_audit.json
```

## Release contents

- Source, tests, configurations, examples and compiled dashboard assets.
- `data/manifests/drastha-sih-release-v2.json` as the final claim/evidence map.
- `output/sprint33_release_audit.json` as machine-readable acceptance proof.
- Annotated Git tag `v1.0-sih` on the final repository state.

Production hardening, real-site validation, raw exporter interoperability,
calibrated models and operational deployment are intentionally deferred until
after the SIH scope is accepted.
