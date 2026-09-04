# Sprint 14 — paced load and sensor-validation tooling

## Delivered scope

This is a measured validation slice, **not production readiness**. The detector
rules, model, data-quality checks, mixed fixture, signed evidence verification
and worker checkpoint contract are unchanged. Existing uncommitted hero/UI work
is outside this sprint.

- `scripts/check_sustained_ingestion.py`: independent, wall-clock-paced synthetic
  JSONL producer -> read-only continuous worker -> durable journal -> SQLite
  analyst projection -> real analysis-run API readback after every poll. Optional
  signed mode also exercises role-based token access and full HMAC verification.
- Measures offered/emitted/accepted/API-observed records separately, fixed-window
  throughput versus drain-inclusive throughput, latency quantiles, CPU, sampled
  RSS/disk/backlog, queue high-watermark and first-alert visibility. Final incident
  queue and evidence-detail API checks are outside the timed interval.
- Explicit failure gates for incomplete delivery, unhealthy telemetry, producer
  scheduling failure, visibility latency, resource budgets, changed source bytes,
  runtime errors and deadline overruns. A short unit-test smoke cannot claim a
  sustained target: that flag requires at least 60 seconds and every gate passing.
- `scripts/check_sensor_integration.py`: creates a six-SYN offline PCAP with valid
  IP/TCP checksums, invokes installed native/WSL Zeek, then sends the actual
  `conn.log` through the dashboard upload API and checks persisted readback/recon.
  It never transmits packets. Missing Zeek returns **blocked**, exit 2, not success;
  conversion/validation failure returns exit 1.
- Sixteen regression tests, including actual signed/unsigned worker/API smoke,
  failure accounting, environment isolation, sensor-unavailable/timeout handling
  and the generated PCAP's packet/checksum contract.

## Reproduce

From the repository root, use a **new report filename** for every attempt:

```powershell
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 100 --seconds 60 --report-output output/load_unsigned_new.json
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 100 --seconds 60 --signed --report-output output/load_signed_new.json
.venv\Scripts\python.exe scripts/check_sustained_ingestion.py --rate 1000 --seconds 60 --signed --report-output output/load_stress_new.json
.venv\Scripts\python.exe scripts/check_sensor_integration.py --report-output output/sensor_new.json
.venv\Scripts\python.exe scripts/check_continuous_ingestion.py --report-output output/mixed_recovery_new.json
.venv\Scripts\python.exe -m unittest tests.test_sprint14_validation -v
.venv\Scripts\python.exe -m unittest tests.test_mixed_evaluation_replay tests.test_continuous_ingestion tests.test_security_sprint13 -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run load experiments sequentially in fresh processes, without a test suite or
another benchmark running concurrently. These commands only create temporary
synthetic sources/databases and create-only reports. They do not use the live
analyst database, install software, change security settings or write a key to
the repository. Signed load uses an ephemeral in-memory key/token. The API's
import-time default database is redirected into the temporary directory, and
operator environment settings are restored before the test starts.

## Measurement contract

The load is **connection records only**, with 90% balanced completed connections
and 10% scan attempts, using documentation-only IP ranges, deterministic sizes,
unique UIDs and strictly increasing synthetic event timestamps. It uses the
unchanged `deployment-baseline-uncalibrated-v1` profile, with no supplied DGA model
or trust policy. Counts of findings here are observations, not ground-truth
accuracy scores. The separate 452-record regression covers all eight behaviours.

Default budgets are declared before the run: P95 write-to-API visibility <=1,000
ms, maximum producer scheduling lag <=100 ms, sampled process RSS/disk <=512 MiB,
30 seconds maximum drain, batch <=64 records. No silent state reset, sampling-out
of inputs, quality bypass or audit bypass is allowed. The finite record/byte
journal limits are explicitly sized to the entire offered workload; the harness
itself caps experiments at 100,000 records/300 seconds. This does not change the
production worker's default limits.

The producer has its own thread, never waits for a worker batch to finish, and
uses monotonic due times. Tail OS timer jitter may consume at most the stated
scheduling-lag budget (also bounded by the drain deadline). The fixed offer
window is **not** extended: producer overrun, observations before its end and
drain-inclusive results are reported separately. All missing observations count
against delivery and latency gates; percentiles are never fabricated for an
empty sample. A scheduling-gate failure means the requested load was not
demonstrated even if processing caught up later.

Latency starts immediately before the producer's local file write and ends
after the actual API report has been read and compared to the committed worker
snapshot. It is a conservative **visibility observation**, not exact commit time
or packet-to-alert latency. First-alert timing uses its latest supporting input
record; the detector's required observation window is not included in that delta.
TestClient executes the real ASGI/auth/API code, but there is no TCP/TLS handshake,
reverse proxy or browser-rendering time. This distinction also applies to older
tests named `http` in this repository.

CPU includes producer, consumer and ASGI threads, and is expressed against one
logical core. RSS includes the prepared workload. Preparation, startup, final
incident detail checks and final ledger verification are excluded from elapsed
time. Resource/backlog samples are taken between polls; transient peaks may be
higher. Deadline/resource stops are cooperative between bounded polls, not OS
process limits. This is neither a many-hour soak nor a multi-client contention
test. Do not convert connection-record throughput into Mbps.

## Results and remaining gates

The 1,000 records/sec signed run **failed**. All 60,000 records were emitted,
but only 40,244 were API-visible by the end of the 60-second offer window and
54,516 by the 30-second drain deadline. The remaining **5,484** were not observed.
P95 visibility among the observed subset was **32,365.30 ms**; unobserved records
also fail the delivery/latency gates. Sampled peak RSS was **224.39 MiB**, disk
**29.31 MiB**. Maximum producer scheduling lag also exceeded its 100 ms gate
(126.22 ms), so this is a failed offered-load experiment, not a certified
1,000 records/sec capacity measurement. The full failure is retained in
`output/sprint14_signed_1000rps_60s.json`.

An earlier unsigned 100 records/sec pilot processed all 6,000 records with P95
45.67 ms but failed the maximum producer-scheduling-lag gate (123.28 ms). That
failure remains in `output/sprint14_unsigned_100rps_60s.json`; it has not been
deleted or relabelled as a pass. The earlier signed pilot passed with P95
133.87 ms (`output/sprint14_signed_100rps_60s.json`). Pilots predate the final
first-alert/provenance instrumentation; final-run measurements are separate.

Final sequential 100 records/sec / 60-second runs on Windows 11, Python 3.12.10
(16 logical CPUs), with the same workload SHA and final harness SHA:

| Measurement | Unsigned SQLite | Signed SQLite + token-auth API |
|---|---:|---:|
| Offered / API-observed | 6,000 / 6,000 | 6,000 / 6,000 |
| API-observed before 60 s | 5,998 | 5,991 |
| Rejected / quality | 0 / healthy | 0 / healthy |
| P95 write-to-API visibility | 47.49 ms | 137.11 ms |
| Elapsed including drain | 60.051 s | 60.059 s |
| Tail drain | 50.98 ms | 58.69 ms |
| Producer tail overrun | 5.46 ms | 0 ms |
| Sampled peak RSS | 90.04 MiB | 83.04 MiB |
| Sampled peak disk | 3.14 MiB | 4.08 MiB |
| Maximum sampled backlog | 11 records | 13 records |
| First recon visible after start | 1.942 s | 1.949 s |
| Declared gates | PASS | PASS |

Raw files: `output/sprint14_unsigned_100rps_60s_final.json` and
`output/sprint14_signed_100rps_60s_final.json`. First-alert observations occur
before the producer finishes; detection is not deferred to an end-of-run report.
These single runs do not establish a maximum capacity, statistical confidence
interval or a production SLA. Signed and unsigned polling cadences differ, so
RSS/CPU differences must not be treated as isolated cryptographic overhead.

The mixed append/restart/upload-path rerun remains **452 accepted, 0 rejected,
8 findings, 8 incidents, 8 TP, 0 FP, 0 FN, 86 TN, healthy**. The canonical fixture
hash remains `5848e73370f34e26583dd3678339e93b63b877c9ae3ed3a26b05d15952d844fd`.
Its report is `output/sprint14_mixed_recovery_report.json`; it uses the existing
finite Sprint 12 experiment schema and must not be read as a sustained-load test.

Automated verification: **283 Python tests passed** (267 existing + 16 new).
The separately rerun mixed/continuous/security selection passed **52 tests**.
No tests were skipped to accommodate a missing Zeek installation: external
sensor availability is an explicit, separate integration gate, while unit tests
exercise its blocked and failed outcomes deterministically.
Frontend production build and all four existing local theme tests also passed;
those UI drafts/tests are not part of this sprint commit. The existing
Starlette/httpx deprecation warning remains non-failing.

Real sensor validation is currently **blocked** on this machine: no native Zeek
executable was found and WSL reports no installed Linux distributions. The
availability report preserves that failure. No Zeek installation, distro setup or
network capture was performed. The sensor checker is regression-tested with a
stubbed external conversion; that is explicitly not a successful real-sensor run.
Its eventual real run covers conn/recon only, not TLS/QUIC/DNS interoperability.
Zeek's native record order/quality is reported unchanged; the harness does not
sort sensor output to manufacture healthy telemetry.

Browser validation awaits the user's optional approval and is not claimed by
the backend/ASGI tests. TLS deployment, real sensor validation, PostgreSQL load,
multi-user contention, longer soaks, all-protocol capacity and scaling remain
open. Full prefix verification, historical findings/snapshots, repeated analyst
projection and full signed-ledger scans remain scaling risks. Measurements here
do not justify weakening those integrity checks; optimization needs equivalent
tamper/recovery guarantees and a separately reviewed design.

Sprint 11's failed DGA generalization gates, Sprint 12's state compaction/rotation,
and Sprint 13's credential lifecycle/external audit anchors remain open before
production deployment. Sprint 15 operational runbooks must carry these limits
forward, not declare them resolved merely because a numbered sprint advanced.
