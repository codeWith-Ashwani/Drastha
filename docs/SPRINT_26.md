# Sprint 26 — deterministic demo bundle and isolated rehearsal

## Outcome

Sprint 26 adds a create-only, deterministic ZIP builder for the SIH demo source.
It packages Git-tracked repository content plus the already compiled dashboard,
embeds the size and SHA-256 of every member, rejects unsafe paths, symlinks and
common secret/capture/database formats, and verifies the archive before use.

The acceptance command creates the bundle twice and requires the bytes to be
identical. It extracts one copy into a new temporary directory, runs the Sprint 25
release audit from that copy, then runs the full demo rehearsal. The rehearsal
itself executes the attack story twice and confirms that replay is idempotent.

## Reproduction

First run the dashboard build, then commit the exact candidate being packaged.
The checker deliberately refuses staged or unstaged tracked changes.

```powershell
Set-Location web
npm run build
Set-Location ..

.venv\Scripts\python.exe scripts\check_sprint26_bundle.py `
  --bundle-output build\drastha-sih-demo-v1.zip `
  --report-output output\sprint26_bundle_audit.json
```

Both outputs are create-only. Use a new path for another run. The `build/`
directory is intentionally ignored by Git so a binary archive does not become a
substitute for reviewable source. The small JSON audit is retained as evidence.

## Security and integrity rules

- Only files known to Git and generated `web/dist` files enter the archive.
- `.git`, virtual environments, `node_modules`, Python caches, keys, databases,
  PCAPs and environment-secret files are rejected.
- Absolute paths, parent traversal, duplicate members, symlinks and encrypted ZIP
  members are rejected during verification.
- Every file is checked against the embedded manifest after extraction and the
  original archive must remain unchanged during rehearsal.
- Output is deterministic for the same committed source and built frontend.

## Honest limitations

This is a **prepared-host offline demo source bundle**, not a self-contained
installer. It includes prebuilt dashboard assets but not Python, Node, packages,
containers or OS libraries. The isolated-directory run reuses this host's Python
runtime and installed API dependencies. It is not a clean VM, different-OS,
live-mirror or hardware-data-diode test, and it remains explicitly non-production.

## Verified result

The retained acceptance run packages clean source revision
`7d461e112df12fe24897dba007ed2af953bfd109` into 335 members. The resulting
13,434,033-byte archive has SHA-256
`156f6c1e76ab59f8798c3174f16e38c39501ae3ae7c110247b2175c480c44a9b`.
All ten bundle/rehearsal gates pass, including byte-identical duplicate builds,
the extracted Sprint 25 audit, preflight, attack story, evaluation and idempotent
second replay. The machine-readable proof is `output/sprint26_bundle_audit.json`.

Regression verification: 418 Python tests passed, 18 frontend tests passed, and
the TypeScript/Vite production build completed successfully. The existing Vite
test WebSocket port warning remains visible and did not fail the suite.
