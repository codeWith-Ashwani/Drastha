# Drastha

Drastha is a passive network-security analytics platform for one-way monitoring environments. The codebase is being built as a sequence of testable vertical slices.

The current Sprint 0-5 implementation can:

- replay Zeek `conn.log` JSON lines;
- normalize them into a shared network-event contract;
- track source fan-out in a sliding window;
- detect vertical port scans and horizontal host scans;
- detect SYN-flood and UDP-flood behaviour;
- emit evidence-rich JSON alerts with confidence and severity.
- report replay health, event span, ordering and processing rate;
- invoke Zeek for raw-PCAP conversion when a Zeek executable is available.
- parse Zeek `dns.log` JSON lines without forcing DNS fields into connection events;
- detect DGA-like registered domains with an inspectable character 3-gram model;
- detect DNS-tunnelling windows using volume, subdomain diversity, length and entropy;
- enforce duplicate-domain and malicious-family separation between ML train/test splits;
- generate measured model metrics and a limitation-focused model card.
- detect periodic C2-like callbacks using interval, jitter and size consistency;
- enrich C2 evidence with TLS/QUIC metadata without decrypting payloads;
- guarantee that a fingerprint alone cannot trigger a C2 alert.
- detect outbound-volume anomalies using byte direction and a per-source baseline;
- suppress approved backup destinations;
- correlate cross-detector alerts into deterministic, evidence-rich incidents;
- deduplicate repeated alert IDs and validate analyst-feedback dispositions.
- automatically persist correlated alerts and incidents when `DRASTHA_DB` is set;
- restore exfiltration baselines, active windows, and cooldowns after process restarts;
- restore prior alerts before correlation so multi-stage incidents can span separate runs;
- persist incidents, alerts, statuses, and analyst feedback across restarts;
- expose a FastAPI analyst service with health, queue, evidence, review, and export endpoints;
- provide a responsive React/TypeScript incident dashboard;
- present an SIH-ready attack-chain overview with capture-relative timestamps,
  detector-grouped evidence, and responsive investigation workflows;
- run locally with SQLite or as an offline Docker Compose bundle with PostgreSQL.

It does not capture live traffic, decrypt payloads, or send any response toward the monitored network.

## Quick start

From the project directory:

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH = "src"
drastha replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5
```

### Reliable SIH demo start

Drastha's presentation path does not require Docker. It checks every required
asset, resets a safe local SQLite demo database, loads the known attack story,
and starts the API plus built dashboard with one command:

On a fresh clone, run the one-time setup while internet is available:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

On presentation day, no internet is required:

```powershell
$env:PYTHONPATH = "src"
drastha demo-preflight --report-output output/drastha_demo_preflight.json
drastha demo-serve --fresh
```

Open `http://127.0.0.1:8000`. The preflight report distinguishes required
failures from optional capabilities such as Docker and Zeek. If Docker is not
running, the same evidence, incident queue, and analyst workflow remain
available through the SQLite offline fallback.

The dashboard also includes **Analyse your own replay**. Judges can upload a
Zeek connection replay as `.jsonl`, `.ndjson`, or a JSON array up to 5 MB. The
local API validates the records, runs reconnaissance, flooding, C2-beacon and
outbound-transfer checks, correlates findings, stores any incidents, and returns
a plain-language evidence view. Use **Download a sample attack replay** in the
dashboard for a known-good upload. Uploaded file contents are processed locally
and are not retained as files.

For the simplest Windows start, right-click `scripts/start-demo.ps1` and choose
**Run with PowerShell**. It performs the preflight, opens the browser, and keeps
the demo server running in the PowerShell window.

To prepare the data without starting the server:

```powershell
drastha demo-prepare --fresh --report-output output/drastha_demo_prepare_report.json
```

Generate evidence for the judges with the same versioned fixtures:

```powershell
drastha evaluate-demo --iterations 250 --report-output output/drastha_evaluation_report.json
```

The report keeps reconnaissance, DDoS, DNS, C2, and exfiltration results
separate and records detector-only timing. It deliberately labels these as
synthetic scenario checks—not production accuracy or false-positive rates.

Before presenting, verify the complete path twice from a clean rehearsal database:

```powershell
drastha demo-rehearse --evaluation-iterations 50
```

See `docs/DEMO_WALKTHROUGH.md` for the two-minute and five-minute presentation
scripts, recovery steps, and judge-facing explanation of what is live versus simulated.

To save alerts:

```powershell
$env:PYTHONPATH = "src"
drastha replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5 --output output/recon_alerts.jsonl
```

Sprint 1 DDoS replay:

```powershell
$env:PYTHONPATH = "src"
drastha replay --input examples/zeek_conn_ddos.jsonl --detectors ddos --syn-threshold 5 --udp-packet-threshold 500 --output output/sprint1_demo_alerts.jsonl --health-output output/sprint1_health.json
```

Check raw-PCAP readiness:

```powershell
$env:PYTHONPATH = "src"
drastha check-zeek
```

On Windows, `auto` mode uses Zeek installed inside WSL. A custom distribution or
Zeek location can be selected with `--wsl-distro Ubuntu` and
`--zeek-binary /opt/zeek/bin/zeek`.

Once Zeek is installed:

```powershell
$env:PYTHONPATH = "src"
drastha pcap --input path/to/capture.pcap --zeek-output output/zeek --output output/pcap_alerts.jsonl --health-output output/pcap_health.json
```

Train and evaluate the Sprint 2 demonstration DNS model:

```powershell
$env:PYTHONPATH = "src"
drastha train-dns --dataset examples/dns_training_demo.csv --model-output output/models/dns_dga_demo.json --metrics-output output/dns_model_metrics.json --model-card-output output/DNS_MODEL_CARD.md
```

Replay the DNS threat demonstration:

```powershell
$env:PYTHONPATH = "src"
drastha dns-replay --input examples/zeek_dns_threats.jsonl --model output/models/dns_dga_demo.json --output output/sprint2_dns_alerts.jsonl --report-output output/sprint2_dns_report.json
```

Replay the Sprint 3 C2 beacon demonstration:

```powershell
$env:PYTHONPATH = "src"
drastha c2-replay --input examples/zeek_conn_beacon.jsonl --encrypted-input examples/zeek_ssl_beacon.jsonl --output output/sprint3_c2_alerts.jsonl --report-output output/sprint3_c2_report.json
```

Replay Sprint 4 exfiltration behaviour and correlate it with the C2 alert:

```powershell
$env:PYTHONPATH = "src"
drastha exfil-replay --input examples/zeek_conn_exfil.jsonl --output output/sprint4_exfil_alerts.jsonl --report-output output/sprint4_exfil_report.json
drastha correlate-alerts --input output/sprint3_c2_alerts.jsonl --input output/sprint4_exfil_alerts.jsonl --output output/sprint4_incidents.jsonl --report-output output/sprint4_incident_report.json
```

Set `DRASTHA_DB` before `exfil-replay` to checkpoint its baseline and active
window state. The next process restores that state automatically. Use
`--reset-state` only when intentionally starting a new baseline.

When the analyst database is configured, the same command writes directly to
SQLite or PostgreSQL as part of correlation. No separate demo-import step is needed:

```powershell
$env:DRASTHA_DB = "output/drastha.db"
drastha correlate-alerts --input output/sprint3_c2_alerts.jsonl --input output/sprint4_exfil_alerts.jsonl --output output/sprint4_incidents.jsonl --report-output output/sprint4_incident_report.json
```

Replaying the same alerts is idempotent and does not reset an analyst's incident status.

For frontend development, run the Sprint 5 analyst console manually:

```powershell
python -m pip install -e ".[api]"
cd web
pnpm install
pnpm run build
cd ..
$env:DRASTHA_ROOT = (Get-Location).Path
$env:DRASTHA_WEB = (Join-Path (Get-Location).Path "web/dist")
python -m uvicorn aegisflow.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`, then use **Load demo data** if the queue is empty.
For the PostgreSQL deployment, run `docker compose up --build` on a machine with
Docker Desktop or Docker Engine installed.

## Current boundaries

- Raw-PCAP execution requires an external Zeek installation; the adapter fails clearly when it is absent.
- Reconnaissance, DDoS, DNS, C2 beacon, exfiltration, correlation, persistent API,
  and dashboard workflows are implemented as demonstrable slices.
- The DNS model is trained on a tiny synthetic fixture to verify the pipeline. Production claims require licensed, versioned datasets and deployment-specific calibration.
- DNS-over-HTTPS is not visible from ordinary Zeek DNS logs unless telemetry is collected before encryption.
- Confidence is a transparent heuristic pending calibration on labelled data.
- Severity is policy-based and does not claim operational impact knowledge.
- The sample thresholds and seven-event throughput figure are smoke-test values, not production benchmarks.
- The repeatable evaluation report measures small in-memory synthetic fixtures;
  packet capture, Zeek conversion, database, API, and UI latency are excluded.
- Docker Compose is verified on Windows with Docker Desktop 4.88.1, Docker Engine
  29.7.2, Compose 5.4.0, and the PostgreSQL 16 Alpine image.
- Automatic correlation-to-database persistence is verified against the PostgreSQL
  Docker deployment; a repeated run preserved the analyst status and created no duplicate.

See [docs/STATUS.md](docs/STATUS.md) for current progress and [docs/SPRINTS.md](docs/SPRINTS.md) for the full implementation plan and acceptance criteria.
