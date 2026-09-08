# Sprint 19 — real offline Zeek sensor and passive-boundary proof

## Outcome

Sprint 19 closes the previously blocked local sensor gate with an installed Zeek
8.0.10 runtime in Ubuntu 24.04 WSL. A deterministic 15-packet classic PCAP is
processed by the real Zeek executable in offline `-r` mode. The resulting
`conn.log`, `dns.log`, and `ssl.log` enter Drastha's shared replay analysis,
are persisted as a completed analysis run, and are read back through the same
API used by the dashboard.

This is a sensor-interoperability proof, not a live-mirror, accuracy, or
throughput result. The generated traffic never leaves the host.

## Implemented changes

- `scripts/check_sensor_integration.py` now creates one deterministic mixed PCAP:
  six incomplete SYN connections, one DNS query/response, and one TCP/TLS 1.3
  handshake containing a cleartext ClientHello.
- The real Zeek output must include connection, DNS, and TLS records. Drastha
  joins the explicitly selected PCAP to the Zeek flow identity, derives the JA3
  and packet timing/size sequence, and records that payload was neither decrypted
  nor retained.
- Python detector analysis runs under a connection-denial guard. Any attempted
  outbound connection makes the check fail and is recorded. Zeek is invoked only
  with `-r <capture>`; no live interface is selected.
- The completed report is fetched from `/api/analysis-runs/{run_id}` and must
  match the JSON-serialized saved snapshot.
- `ZeekRunner` and `WSLZeekRunner` now refuse a non-empty output directory.
  Existing evidence is never deleted or silently mixed with a new capture.
- Returned sensor provenance includes the exact command and supported log files.

## Measured result

The signed-off local run is retained in
[`output/sprint19_sensor_integration.json`](../output/sprint19_sensor_integration.json).

| Measurement | Result |
|---|---:|
| Zeek | 8.0.10, Ubuntu 24.04 WSL |
| Offline PCAP packets | 15 |
| Zeek connection records | 8 |
| Zeek DNS records | 1 |
| Zeek TLS records | 1 |
| Accepted / rejected Drastha records | 10 / 0 |
| Telemetry quality | healthy |
| Findings / incidents | 1 / 1 reconnaissance |
| Joined capture packets | 15 |
| Detector network attempts | 0 |
| Acceptance gates | 16 / 16 passed |

The TLS observation has a measured fingerprint and packet sequence but correctly
remains `insufficient_evidence`: one session cannot warm the 20-session sequence
or 100-session prevalence baselines. This sprint does not lower those thresholds
or manufacture an encrypted-malware alert.

The PCAP SHA-256 is
`0f72c2dc027d53022d2f10e4347fb05156f89fc03d09065204ffed41532e0634`.
Zeek-generated UIDs and log hashes are recorded per run and are not asserted to
be reproducible across independent Zeek executions.

## Reproduction

Install a compatible Zeek at `/opt/zeek/bin/zeek` in WSL or provide an explicit
binary. The local verified distribution is `Ubuntu-24.04`.

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sensor_integration.py `
  --mode wsl `
  --distribution Ubuntu-24.04 `
  --report-output output\sprint19_sensor-reproduction.json
```

Report paths are create-only. Choose a new filename for every run.

## Boundaries and next work

- The PCAP is synthetic and offline; physical mirror/data-diode deployment is not
  claimed.
- QUIC sensor interoperability remains untested. Classic PCAP only is supported
  by the in-process packet feature extractor; PCAPNG requires conversion.
- One TLS session proves metadata availability, not anomaly accuracy or baseline
  calibration.
- API readback is in-process ASGI, not browser or TCP/TLS transport validation.
- The upload profile is used so the six-flow recon fixture crosses the documented
  demonstration threshold; deployment calibration is a later sprint.
- NetFlow/IPFIX/sFlow native exporter adapters and the PS-guided multi-scenario
  traffic corpus remain future work.

Sprint 20 will build the isolated, reproducible SIH-guided benign/attack lab
corpus on top of this verified sensor path.

## Regression verification

- 390 Python tests passed in 36.984 seconds.
- 18 frontend tests passed.
- TypeScript and Vite production build passed.
- The expected non-failing Starlette/httpx deprecation and frontend HMR-port
  warnings remain visible; no test was skipped or weakened.
