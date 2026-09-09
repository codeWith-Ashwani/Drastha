# Sprint 24 — sustained mixed-protocol performance and reliability

## Outcome

Sprint 24 extends the paced continuous-ingestion benchmark from connection-only
records to deterministic connection, DNS and TLS metadata. It exercises the real
bounded follower, derived feature extraction, SQLite journal, signed analyst
projection and authenticated ASGI readback for 60 seconds without weakening the
existing quality, latency, resource or source-integrity gates.

The genuinely demonstrated target on this host is **50 input records/second for
60 seconds**. Two 100 records/second attempts processed every record but failed
the strict 100 ms maximum producer-scheduling-lag gate; they remain checked-in
failed evidence and are not relabelled as successful capacity.

## Workload

The `mixed` workload contains, per ten input records:

- seven connection-only records;
- two standalone DNS records;
- one TLS record that yields both connection and encrypted-session metadata.

At the passing 3,000-record run this produced exactly 2,400 normalized connection
events, 600 DNS events and 300 encrypted-session events. TLS records include JA4,
SNI and packet-size/timing observations. The input has unique UIDs, strict event
time order and no labels, supplied confidence, `ml_evidence` or answer keys.

All connection traffic originates inside an explicit `10.0.0.0/8` load-test
boundary, so the run also verifies 2,400 outbound direction classifications.
This is generated passive metadata; it is not a PCAP-to-Zeek, Mbps, accuracy or
live-mirror measurement.

## Passing measurement

Environment: Windows 11, Python 3.12.14, 16 logical CPUs, signed SQLite store,
default batch size 64.

| Measure | Result |
|---|---:|
| Offered duration | 60 seconds |
| Offered / observed records | 3,000 / 3,000 |
| Completed rate including drain | 49.94 records/sec |
| API visibility P50 / P95 / max | 61.86 / 111.25 / 231.13 ms |
| Producer lag P50 / P95 / max | 9.63 / 20.73 / 99.78 ms |
| Maximum sampled backlog | 8 records |
| Final backlog / rejected | 0 / 0 |
| Sampled peak RSS | 79.85 MiB |
| Sampled peak disk | 3.08 MiB |
| Quality | healthy |

Every gate passed: offered/observed counts, healthy zero-rejection telemetry,
producer schedule, P95 visibility under one second, RSS/disk under 512 MiB,
source bytes preserved, exact protocol counts, explicit boundary application and
no runtime/integrity error.

## Honest 100 records/second boundary

Both 100 records/second runs emitted and API-observed all 6,000 records with zero
final backlog. Their P95 visibility was 122.08 ms and 119.52 ms. They failed
because maximum producer lag reached 106.82 ms and 110.37 ms against the unchanged
100 ms gate. A scoped 1 ms Python thread-switch interval improved fairness in the
second harness but did not make the rate pass, so 100 mixed records/second remains
unproven.

This distinction matters: drain success proves no loss in the bounded run, but it
does not prove the producer sustained its offered schedule.

## Reproduction

```powershell
$env:PYTHONPATH = "$PWD\src"
.venv\Scripts\python.exe scripts\check_sustained_ingestion.py `
  --rate 50 --seconds 60 --signed --protocol-mix mixed `
  --report-output output\sprint24-new-run.json

.venv\Scripts\python.exe scripts\check_sprint24_performance.py
```

Evidence reports are create-only. The audit pins the passing result and both
failed higher-rate attempts by SHA-256.

## Remaining limits

- Single process and same-host paced producer; no external sensor clock.
- ASGI TestClient, not TCP/TLS/browser transport.
- Bounded 60-second run, not a multi-hour or unlimited-service soak.
- Synthetic metadata, not live Zeek conversion or packet loss measurement.
- Peaks are sampled and transient resource peaks may be higher.
- 100 mixed records/second is not demonstrated on this architecture.
- Sprint 25 owns the final reproducible SIH release validation.

## Regression verification

- Targeted performance/Sprint 14 suite: 21 tests passed.
- Full Python suite: 412 tests passed.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
- Existing Starlette/httpx and frontend HMR-port warnings remain visible.
