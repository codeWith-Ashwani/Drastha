# Sprint 27 — safe loopback demo startup

## Outcome

Sprint 27 fixes the misleading startup sequence that previously printed
`Drastha demo ready` and prepared/reset the demo database before Uvicorn discovered
that port 8000 was already occupied.

`demo-serve` now validates a literal loopback host, binds and retains the exact
requested socket first, and passes that pre-bound socket to Uvicorn. If the port
is unavailable, the command exits with code 2 before preflight preparation or
`--fresh` database mutation. Its error identifies the host/port, suggests the
next bindable port, and provides a read-only PowerShell owner-inspection command.

The message immediately before Uvicorn is now `Starting Drastha demo`; application
startup logs remain the authoritative readiness signal.

## Usage

Default port:

```powershell
.\scripts\start-demo.ps1
```

Explicit alternative port:

```powershell
.\scripts\start-demo.ps1 -Port 8001
```

Equivalent direct command:

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe -m aegisflow.cli demo-serve --fresh --port 8001
```

To inspect—not terminate—the process currently listening on port 8000:

```powershell
Get-NetTCPConnection -LocalPort 8000 | Select-Object LocalAddress,LocalPort,State,OwningProcess
```

Stopping another process remains an explicit operator decision. Drastha does not
kill it automatically.

## Safety properties

- Demo serving accepts only `127.0.0.1`, `::1`, or `localhost`.
- Port values outside 1–65535 fail validation.
- The requested socket is retained through database preparation and handed to
  Uvicorn, removing the check-then-bind race.
- Port conflict failure occurs before `--fresh` can delete/reset the demo DB.
- Alternative-port probing binds only local loopback sockets and sends no traffic.
- The PowerShell launcher exposes a validated `-Port` parameter and opens the
  matching browser URL.

## Verification and limitations

`scripts/check_sprint27_startup.py` runs ten machine-readable safety gates using
temporary local sockets and a sentinel database. It also starts an owned temporary
Uvicorn process on loopback, waits for authenticated-independent `/api/health`
readback, checks the application-startup completion log, and terminates only that
owned process. Unit coverage verifies that a successful launch passes the pre-bound
socket to Uvicorn and closes it after server exit.

This change hardens the local SIH demo launcher only. It does not replace the TLS,
authentication and signed-store checks in `scripts/operate.py`; it does not make
the prototype Internet-facing or production ready. A successful bind is not
application readiness, so operators must still wait for Uvicorn's application
startup completion log and then check the dashboard/API.

The retained `output/sprint27_startup_audit.json` passes all ten startup gates.
Final regression verification: 423 Python tests and 18 frontend tests passed, and
the TypeScript/Vite production build completed successfully. The existing Vite
test WebSocket-port warning remains visible and did not fail the suite.
