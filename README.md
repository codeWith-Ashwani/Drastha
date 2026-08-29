# AegisFlow

AegisFlow is a passive network-security analytics platform for one-way monitoring environments. The codebase is being built as a sequence of testable vertical slices.

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
- persist incidents, alerts, statuses, and analyst feedback across restarts;
- expose a FastAPI analyst service with health, queue, evidence, review, and export endpoints;
- provide a responsive React/TypeScript incident dashboard;
- run locally with SQLite or as an offline Docker Compose bundle with PostgreSQL.

It does not capture live traffic, decrypt payloads, or send any response toward the monitored network.

## Quick start

From the `aegisflow` directory:

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH = "src"
python -m aegisflow.cli replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5
```

To save alerts:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5 --output output/recon_alerts.jsonl
```

Sprint 1 DDoS replay:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli replay --input examples/zeek_conn_ddos.jsonl --detectors ddos --syn-threshold 5 --udp-packet-threshold 500 --output output/sprint1_demo_alerts.jsonl --health-output output/sprint1_health.json
```

Check raw-PCAP readiness:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli check-zeek
```

On Windows, `auto` mode uses Zeek installed inside WSL. A custom distribution or
Zeek location can be selected with `--wsl-distro Ubuntu` and
`--zeek-binary /opt/zeek/bin/zeek`.

Once Zeek is installed:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli pcap --input path/to/capture.pcap --zeek-output output/zeek --output output/pcap_alerts.jsonl --health-output output/pcap_health.json
```

Train and evaluate the Sprint 2 demonstration DNS model:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli train-dns --dataset examples/dns_training_demo.csv --model-output output/models/dns_dga_demo.json --metrics-output output/dns_model_metrics.json --model-card-output output/DNS_MODEL_CARD.md
```

Replay the DNS threat demonstration:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli dns-replay --input examples/zeek_dns_threats.jsonl --model output/models/dns_dga_demo.json --output output/sprint2_dns_alerts.jsonl --report-output output/sprint2_dns_report.json
```

Replay the Sprint 3 C2 beacon demonstration:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli c2-replay --input examples/zeek_conn_beacon.jsonl --encrypted-input examples/zeek_ssl_beacon.jsonl --output output/sprint3_c2_alerts.jsonl --report-output output/sprint3_c2_report.json
```

Replay Sprint 4 exfiltration behaviour and correlate it with the C2 alert:

```powershell
$env:PYTHONPATH = "src"
python -m aegisflow.cli exfil-replay --input examples/zeek_conn_exfil.jsonl --output output/sprint4_exfil_alerts.jsonl --report-output output/sprint4_exfil_report.json
python -m aegisflow.cli correlate-alerts --input output/sprint3_c2_alerts.jsonl --input output/sprint4_exfil_alerts.jsonl --output output/sprint4_incidents.jsonl --report-output output/sprint4_incident_report.json
```

Run the Sprint 5 analyst console locally:

```powershell
python -m pip install -e ".[api]"
cd web
pnpm install
pnpm run build
cd ..
$env:AEGISFLOW_ROOT = (Get-Location).Path
$env:AEGISFLOW_WEB = (Join-Path (Get-Location).Path "web/dist")
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
- Docker Compose is verified on Windows with Docker Desktop 4.88.1, Docker Engine
  29.7.2, Compose 5.4.0, and the PostgreSQL 16 Alpine image.

See [docs/STATUS.md](docs/STATUS.md) for current progress and [docs/SPRINTS.md](docs/SPRINTS.md) for the full implementation plan and acceptance criteria.
