# Sprint 34 — isolated real-tool attack evidence

## Outcome

Sprint 34 replaces three semantic-only SIH evidence claims with an authorised,
no-default-route WSL capture. `slowhttptest` 1.9.0 runs in Slowloris/slow-header
mode, iodine 0.7.0 establishes an IP-over-DNS tunnel and carries successful ping
traffic, and a deterministic socket emulator produces eleven three-second C2-like
callbacks. A separate jittered, variable-size health-check capture remains benign.

Both clients run inside network namespaces connected only to fixed private `/30`
links. They have no default route and cannot contact the Internet or a production
target. tcpdump records the lab links, Zeek 8.0.10 generates native connection and
DNS metadata, and the committed chronological fixture traverses the actual upload
analysis path. Raw packet captures remain local and gitignored.

## Measured result

- 141 Zeek records accepted: 89 connection and 52 DNS records.
- 0 rejected, 0 out of order and 0 duplicate records; quality is healthy.
- Slow HTTP: 20 threshold-crossing connections, minimum observed duration
  130.203 seconds, maximum 241 bytes and no responder application bytes.
- C2 timing: 11 completed exchanges, 3.001-second mean interval, 0.0001 interval
  variation and a 30.009-second observation span.
- iodine: TXT tunnel established, 52 Zeek DNS transactions and a successful
  tunneled ping; the detector crosses its encoded-TXT path after six queries.
- Jittered benign health check: 10 captured completed exchanges and no alert.
- Final findings: exactly `slow_http_connection_exhaustion`, `periodic_beacon`
  and `dns_tunnelling`.
- The three findings correlate into one incident because they share the same lab
  source and overlapping time range. This is expected correlation, not a claim
  that unrelated real-world attacks are coordinated.

## Detector and ingestion corrections driven by real evidence

Zeek reports a Slowloris-mode socket as `SF` when it eventually closes cleanly,
even though the server sent zero application bytes. The detector now accepts this
specific shape and permits up to 16 total TCP packets, matching handshake, sparse
keepalive and teardown traffic. A completed HTTP response still remains benign.
Zeek's passive `service=http` classification is used instead of a fixed destination
port list, so HTTP on the measured non-standard port is not discarded.

Zeek emits multiple DNS transaction rows with the same connection UID. Replay
quality now keys DNS duplicates by `(record type, UID, trans_id)` and keeps strict
exact/conflicting duplicate detection. The real 52-row iodine flow is therefore
healthy without weakening timestamp or corruption checks.

## Reproduction

The generators refuse existing raw-output directories rather than overwriting
evidence. Remove or archive a prior local capture deliberately before regenerating.

```powershell
wsl.exe --distribution Ubuntu-24.04 --user root -- `
  bash /mnt/f/Drastha/Drastha/scripts/generate_sprint34_real_tool_capture.sh `
  /mnt/f/Drastha/Drastha

wsl.exe --distribution Ubuntu-24.04 --user root -- `
  bash /mnt/f/Drastha/Drastha/scripts/generate_sprint34_benign_control.sh `
  /mnt/f/Drastha/Drastha

.venv\Scripts\python.exe scripts\build_sprint34_capture_fixture.py --check
.venv\Scripts\python.exe scripts\check_sprint34_real_tools.py `
  --report-output output\sprint34_real_tools_audit.json
.venv\Scripts\python.exe -m unittest tests.test_sprint34_real_tools -v
```

## Claim boundaries

- The C2 program proves periodic callback timing, not a malware family or an
  external C2 framework.
- Slow HTTP detection proves the measured connection-exhaustion shape, not that
  a specific attacker or server impact can be identified from passive metadata.
- iodine proves visible classic DNS tunnelling; encrypted DNS that the sensor
  cannot decode remains unavailable.
- This controlled lab improves SIH evidence. It is not production accuracy,
  physical-data-diode interoperability or a live critical-infrastructure trial.

## Verification

- Sprint 34 executable acceptance: passed.
- Full Python suite: 454 tests passed.
- Frontend suite: 18 tests passed.
- Dashboard production build: passed.
