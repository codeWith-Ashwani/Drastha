# Drastha

**Passive AI-assisted cyber-threat intelligence for one-way IP networks.**

Drastha watches network metadata without sending packets back to the protected
network. It detects suspicious behaviour, gives every finding a clear label and
confidence score, connects related findings into incidents, calculates an
investigation priority, and shows the supporting evidence on a dashboard.

The repository contains a complete offline SIH demonstration and the foundation
of a production system. The SIH demo is complete; production hardening is still
in progress.

Sprint 14 adds repeatable paced-load measurements through continuous ingestion,
SQLite and the analyst API, with explicit latency/resource/failure gates, plus
an offline Zeek integration checker. These are bounded synthetic measurements,
not a production capacity guarantee; real-sensor and browser validation remain
open. See [Sprint 14 measurement contract and results](docs/SPRINT_14.md),
[Sprint 12 continuous-ingestion boundaries](docs/SPRINT_12.md) and
[Sprint 13 protected access and signed evidence](docs/SPRINT_13.md).

Sprint 11 adds a public DGA corpus, validation-only operating-point selection,
frozen holdout evaluation through upload analysis, and research-model deployment
guards. The public-data candidate **failed recall gates and was not promoted**;
the demonstration model remains unchanged. See [Sprint 11 scope, measured failures
and reproduction](docs/SPRINT_11.md). Production calibration remains unfinished.

Sprint 10 adds a checksum-pinned, split-audited independent evaluation workflow.
The external CTU-13 baseline exposed detection gaps and false positives; it does
not validate the demo's accuracy on real traffic. See [Sprint 10 results and
reproduction steps](docs/SPRINT_10.md) and the
[pinned evaluation manifest](data/manifests/ctu13_scenario11_benchmark.json).

> Drastha is a defensive research prototype. Use it only with traffic and
> systems that you are authorized to monitor. It does not automatically block
> or attack another system.

## Contents

- [What problem does Drastha solve?](#what-problem-does-drastha-solve)
- [What can it detect?](#what-can-it-detect)
- [How it works](#how-it-works)
- [System requirements](#system-requirements)
- [Clone and run on Windows](#clone-and-run-on-windows)
- [Clone and run on Linux](#clone-and-run-on-linux)
- [Run with Docker](#run-with-docker)
- [How to use the dashboard](#how-to-use-the-dashboard)
- [Analyse your own replay](#analyse-your-own-replay)
- [Process a PCAP with Zeek](#process-a-pcap-with-zeek)
- [Train the demonstration ML model](#train-the-demonstration-ml-model)
- [Run the tests](#run-the-tests)
- [Project structure](#project-structure)
- [Current status and limitations](#current-status-and-limitations)
- [Troubleshooting](#troubleshooting)

## What problem does Drastha solve?

Some critical networks use a network TAP or hardware data diode. Monitoring
software can observe a copy of the traffic, but it must never communicate back
to the protected network.

Drastha is designed for that situation. It works with passively collected
metadata such as:

- source and destination addresses;
- source and destination ports;
- connection time and duration;
- packet and byte counts;
- DNS queries;
- visible TLS or QUIC metadata;
- connection state.

It does not need to decrypt payloads, scan devices, inject packets, or open a
return connection to the monitored network.

## What can it detect?

| Threat behaviour | Method | Evidence shown to the analyst |
|---|---|---|
| Vertical port scan | Behavioural fan-out analysis | Unique ports, target and time window |
| Horizontal host scan | Behavioural fan-out analysis | Unique hosts, destination service and time window |
| SYN flood | Traffic-rate analysis | Attempt count, incomplete ratio and source diversity |
| UDP flood | Traffic-rate analysis | Packet volume, bytes and source diversity |
| DGA-like domain | Character 3-gram Naive Bayes ML model | Uncalibrated model score, domain and entropy context |
| DNS tunnelling | Volume and entropy analysis | Query count, unique labels, length and entropy |
| C2-style callback | Statistical timing analysis | Interval consistency, size consistency and connection count |
| Possible data exfiltration | Adaptive baseline analysis | Outbound bytes, direction ratio and baseline comparison |

Drastha deliberately uses a hybrid approach. ML is used where learning character
patterns is useful. Clear statistical or behavioural methods are used where they
are easier to explain and govern.

## How it works

```text
Simulated stream, Zeek logs or PCAP
                 |
                 v
        Passive normalization
                 |
                 v
      Data quality validation
                 |
                 v
  ML + behavioural threat detection
                 |
                 v
  Label + confidence + evidence
                 |
                 v
      Incident correlation
                 |
                 v
 Transparent risk-priority scoring
                 |
                 v
 SQLite/PostgreSQL -> API -> dashboard
```

The live demonstration streams 67 simulated connection, DNS, and encrypted-
session metadata observations one at a time. It produces ten labelled findings
and eight incidents spanning every required threat family. The
highest-priority incident combines a repeated callback with abnormal outbound
transfer and receives a risk score of 100.

Risk 100 means “investigate first.” It does **not** mean 100% certainty.

## System requirements

### Required for the easiest local demo

| Requirement | Minimum | Why it is needed |
|---|---:|---|
| Git | Recent version | Clone the repository |
| Python | 3.11 or newer | Detection pipeline and API |
| Node.js | 20 or newer | Build the dashboard |
| pnpm or Corepack | Recent version | Install dashboard packages |
| Browser | Current Chrome, Edge or Firefox | Open the dashboard |
| Free disk space | About 2 GB recommended | Dependencies, build files and local database |
| Memory | 4 GB recommended | Comfortable local demonstration |

A GPU is **not required**.

Internet access is required only for the first dependency installation. The
normal SQLite demonstration works offline after setup.

### Windows requirements

- Windows 10 or Windows 11;
- PowerShell 5.1 or newer;
- Python added to `PATH`;
- Node.js with Corepack or pnpm.

WSL is optional. It is needed only when you want to process raw PCAP files with
Zeek on Windows.

### Linux requirements

- A recent Linux distribution;
- Python 3.11 or newer with `venv` support;
- Node.js 20 or newer;
- pnpm or Corepack.

Zeek and Docker are optional.

### Optional production-style tools

- Docker Engine or Docker Desktop with Compose v2;
- PostgreSQL 16 through the included Docker configuration;
- Zeek 8 or a compatible recent release for raw PCAP conversion;
- WSL2 with Ubuntu when using Zeek from Windows.

## Clone and run on Windows

### 1. Clone the repository

```powershell
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha
```

### 2. Run the one-time setup

Keep the internet connected for this step:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

The setup script:

1. creates `.venv`;
2. installs the Python API and detector dependencies;
3. installs and builds the React dashboard;
4. rehearses the complete demo twice.

### 3. Start Drastha

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-demo.ps1
```

Keep the PowerShell window open. The dashboard should open automatically at:

```text
http://127.0.0.1:8000
```

You can also right-click `scripts/start-demo.ps1` and choose **Run with
PowerShell**.

## Clone and run on Linux

The Windows scripts are the most thoroughly tested setup path. On Linux, run
the equivalent commands manually:

```bash
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[api]"

cd web
corepack enable
pnpm install --frozen-lockfile
pnpm run build
cd ..

export PYTHONPATH="$PWD/src"
python -m aegisflow.cli demo-rehearse --evaluation-iterations 50
python -m aegisflow.cli demo-serve --fresh
```

Then open `http://127.0.0.1:8000`.

If `corepack` is unavailable, install pnpm using the official pnpm
installation instructions and repeat the dashboard commands.

## Run with Docker

Docker runs the dashboard and API with PostgreSQL. It is optional for the SIH
demo.

```powershell
git clone https://github.com/codeWith-Ashwani/Drastha.git
cd Drastha
docker compose up --build
```

Open `http://127.0.0.1:8000`.

Stop the containers with:

```powershell
docker compose down
```

The PostgreSQL data is stored in the `drastha-data` Docker volume. The password
in `docker-compose.yml` is for the local demonstration only and must be replaced
before any shared deployment.

## How to use the dashboard

### Live one-way stream demonstration

1. Open the dashboard.
2. Confirm **Sensor online**, **SQLite storage**, and **One-way monitoring**.
3. Click **Start live IP simulation**.
4. Watch records arrive one at a time.
5. Observe the alerts appear while the stream is still running.
6. Confirm the final result:

   - 67 records analysed;
   - 10 labelled alerts;
   - 8 incidents;
   - highest risk score 100.

The findings demonstrate:

- real inference from the trained DGA ML model;
- DNS tunnelling analysis;
- repeated C2-style callback detection;
- abnormal outbound-transfer detection;
- vertical port scanning without a duplicate DDoS classification;
- SYN, distributed-source SYN, UDP-flood, and reflection/amplification paths;
- encrypted-session anomaly detection from TLS/JA4, size, and timing metadata.

Click **Open scored intelligence** to see the attack timeline, confidence,
observed values, comparisons, explanations, limitations and score calculation.

### Instant attack replay

Use **Run instant replay** when you need a shorter demonstration. It runs the C2
and exfiltration attack story immediately and stores one correlated incident.

### Analyst workflow

Open an incident to:

- change the status;
- record a malicious, benign or needs-review decision;
- add investigation notes;
- inspect every contributing alert;
- export the complete incident as JSON.

## Analyse your own replay

The dashboard accepts safe Zeek connection records and can route embedded DNS
and TLS/JA3/JA4 metadata to their threat-specific detectors. Supported JSON
shapes are:

- `.jsonl`;
- `.ndjson`;
- a `.json` array.
- a `.json` object containing a `records` array.

Both native Zeek Unix timestamps and ISO-8601 timestamps are accepted. Supplied
ground-truth fields such as `label`, `threat_class`, `confidence`, and expected
`evidence` are never trusted as predictions; Drastha calculates its own labels,
confidence and evidence from the telemetry features.

Maximum upload size: 5 MB.

Use **Download a sample attack replay** if you want a known-good example. Drag
the file into **Analyse your own replay** or choose it using the file picker.

The uploaded content is:

1. validated;
2. normalized;
3. analysed by the configured detectors;
4. correlated and scored;
5. displayed as plain-language intelligence.

The original uploaded file is not retained by the local application.

Raw PCAP files are not accepted directly by the browser. Convert them through
Zeek using the command-line path below.

## Process a PCAP with Zeek

### Check whether Zeek is available

Activate the virtual environment first, then run:

```powershell
$env:PYTHONPATH = "src"
drastha check-zeek
```

### Windows

Install WSL2, Ubuntu and Zeek inside the Linux environment. Drastha's automatic
mode will use the WSL Zeek executable when it is available.

```powershell
$env:PYTHONPATH = "src"
drastha pcap `
  --input path\to\capture.pcap `
  --zeek-output output\zeek `
  --output output\pcap_alerts.jsonl `
  --health-output output\pcap_health.json
```

### Linux

Install Zeek and ensure the `zeek` command is available on `PATH`, then run:

```bash
export PYTHONPATH="$PWD/src"
drastha pcap \
  --input path/to/capture.pcap \
  --zeek-output output/zeek \
  --output output/pcap_alerts.jsonl \
  --health-output output/pcap_health.json
```

Only process captures that you are authorized to inspect. Raw `.pcap` and
`.pcapng` files are ignored by Git so they are not accidentally committed.

## Train the demonstration ML model

The repository includes a versioned demonstration model so a fresh clone works
immediately. To retrain it from the bundled dataset:

### Windows PowerShell

```powershell
$env:PYTHONPATH = "src"
drastha train-dns `
  --dataset examples/dns_training_demo.csv `
  --model-output output/models/dns_dga_demo.json `
  --metrics-output output/dns_model_metrics.json `
  --model-card-output output/DNS_MODEL_CARD.md
```

### Linux

```bash
export PYTHONPATH="$PWD/src"
drastha train-dns \
  --dataset examples/dns_training_demo.csv \
  --model-output output/models/dns_dga_demo.json \
  --metrics-output output/dns_model_metrics.json \
  --model-card-output output/DNS_MODEL_CARD.md
```

The bundled dataset is intentionally small. Its results prove that training,
inference, leakage checks, metrics and model-card generation work. They are not
a production accuracy claim.

## Run the tests

### Windows

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Linux

```bash
source .venv/bin/activate
python -m unittest discover -s tests -v
```

The current repository contains 115 automated tests covering ingestion,
detectors, ML training, correlation, persistence, API workflows, replay upload,
near-real-time streaming, telemetry quality, PCAP integration and restart
behaviour.

The canonical mixed evaluation replay is
`examples/drastha_mixed_evaluation_v3.jsonl`. Its 452 labelled records are in
strict timestamp order so the unchanged input-quality monitor reports healthy
telemetry while the upload path detects all eight intended behaviours.

Validate a replay without importing incidents:

```powershell
python -m aegisflow.validate_replay examples/drastha_mixed_evaluation_v3.jsonl
```

Build the dashboard separately with:

```bash
cd web
pnpm run build
```

## Useful verification commands

Run the pre-presentation check:

```powershell
$env:PYTHONPATH = "src"
drastha demo-preflight --report-output output/drastha_demo_preflight.json
```

Run every controlled threat scenario and generate a report:

```powershell
$env:PYTHONPATH = "src"
drastha evaluate-demo --iterations 250 `
  --report-output output/drastha_evaluation_report.json
```

Rehearse the complete demo twice and check duplicate protection:

```powershell
$env:PYTHONPATH = "src"
drastha demo-rehearse --evaluation-iterations 50
```

## Project structure

```text
Drastha/
├── src/aegisflow/          Python ingestion, detectors, ML, API and storage
│   ├── detectors/          Recon, DDoS, DNS, C2 and exfiltration detectors
│   └── ingestion/          Zeek connection, DNS, TLS/QUIC and PCAP adapters
├── web/                    React and TypeScript dashboard
├── examples/               Safe, versioned demonstration traffic
├── tests/                  Automated test suite
├── output/                 Model, reports and demonstration evidence
├── deploy/postgres/        PostgreSQL schema
├── scripts/                Windows setup and start scripts
├── docs/                   Architecture, status, sprints and demo guides
├── Dockerfile              Container image definition
├── docker-compose.yml      API, dashboard and PostgreSQL deployment
└── pyproject.toml          Python package and dependency definition
```

The installed product command is named `drastha`. The internal Python package is
still called `aegisflow` for compatibility with earlier development history.

## API endpoints

The FastAPI service exposes endpoints under `/api`, including:

- `/api/health` — service and storage health;
- `/api/incidents` — prioritized incident queue;
- `/api/incidents/{id}` — complete evidence and timeline;
- `/api/replays/analyse` — analyse a browser-uploaded replay;
- `/api/stream/simulated` — monitoring-side near-real-time demonstration feed;
- `/api/metrics` — incident summary metrics.

FastAPI's generated API documentation is available at `/docs` when the static
dashboard catch-all is not taking precedence in a custom development setup.

## Passive-safety properties

- No network-scanning function exists in the pipeline.
- No detector sends packets to a monitored source or destination.
- TLS and QUIC payloads are not decrypted.
- Fingerprints can support context but cannot trigger a C2 alert alone.
- Automatic blocking is intentionally outside the passive monitoring boundary.
- Bad or excessively damaged telemetry is reported instead of silently accepted.

## Current status and limitations

### Completed for the SIH demonstration

- passive simulated streaming;
- Zeek JSONL ingestion and normalization;
- raw PCAP-to-Zeek adapter;
- ML, behavioural and statistical detection paths;
- evidence-rich labelled alerts;
- confidence, severity and transparent risk scoring;
- cross-detector correlation;
- SQLite and PostgreSQL persistence;
- responsive analyst dashboard;
- analyst review and evidence export;
- Docker deployment;
- offline setup, preflight and recovery workflow.

### Still required for production

- continuous live Zeek log following instead of the simulated dashboard stream;
- licensed and versioned external datasets;
- deployment-specific threshold and confidence calibration;
- measured false-positive and false-negative rates;
- queue backpressure, checkpoints and multi-sensor ordering;
- sustained throughput, latency and resource testing;
- authentication and role-based access control;
- encryption, secret management and tamper-evident audit logs;
- high availability, backups and upgrade testing;
- SIEM/SOAR integration and operational governance.

The current production-readiness estimate is approximately 40%. See
[`docs/PRODUCTION_LIMITATIONS.md`](docs/PRODUCTION_LIMITATIONS.md) for the full
backlog and [`docs/STATUS.md`](docs/STATUS.md) for verified progress.

## Troubleshooting

### Python is not found

Install Python 3.11 or newer and enable **Add Python to PATH**, then open a new
terminal.

### PowerShell blocks the script

Run it using the explicit bypass command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

### pnpm is not found

Install a current Node.js release, then run:

```powershell
corepack enable
```

Run the setup script again afterward.

### Port 8000 is already in use

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m aegisflow.cli demo-serve --fresh --port 8001
```

Then open `http://127.0.0.1:8001`.

### Docker is unavailable

Use the normal SQLite setup. Docker is not required for the dashboard, live
simulation, upload analysis, evidence review or export.

### Zeek or WSL is unavailable

Use the included Zeek-style demonstration files. Zeek is required only for
converting a new raw PCAP.

### The incident does not appear

Run **Start live IP simulation** again. Replaying the same evidence is safe and
does not create duplicate incidents.

### Full recovery and presentation guide

See [`docs/FINAL_JUDGE_DEMO_GUIDE.md`](docs/FINAL_JUDGE_DEMO_GUIDE.md).

## Documentation

- [Protected access, signed evidence and retention (Sprint 13)](docs/SPRINT_13.md)
- [Continuous ingestion and recovery (Sprint 12)](docs/SPRINT_12.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Build walkthrough](docs/BUILD_WALKTHROUGH.md)
- [Sprint plan](docs/SPRINTS.md)
- [Current status](docs/STATUS.md)
- [Production limitations](docs/PRODUCTION_LIMITATIONS.md)
- [Prototype requirements traceability](docs/PROTOTYPE_REQUIREMENTS.md)
- [Models and engineered features](docs/MODELS_AND_FEATURES.md)
- [Final SIH demonstration guide](docs/FINAL_JUDGE_DEMO_GUIDE.md)
