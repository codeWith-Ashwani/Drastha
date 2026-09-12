# Drastha

**Passive AI-assisted cyber-threat intelligence for one-way IP networks.**

Drastha watches network metadata without sending packets back to the protected
network. It detects suspicious behaviour, gives every finding a clear label and
confidence score, connects related findings into incidents, calculates an
investigation priority, and shows the supporting evidence on a dashboard.

The repository contains a working offline SIH demonstration and a production
hardening track. Controlled replay results are reproducible; real-traffic
generalization, continuous-service scale and operational deployment remain open.

## SIH26145 dataset and traffic-tool provenance

The finite SIH-only delivery gates and stop condition are in
[SIH closure plan](docs/SIH_CLOSURE_PLAN.md).

[Sprint 36 fresh-source validation](docs/SPRINT_36.md) now checks separate,
checksum-frozen `iperf3`, `hping3`, Slowloris-mode, iodine, C2-emulator,
published-DGA and real-TLS sessions. Flow and metadata lab behaviours passed;
the deployed DGA model missed 40/40 published Vawtrak domains, and six changed
TLS sessions did not have the independent packet-size/timing anomaly needed for
an alert. These failures are retained as SIH acceptance evidence, not folded
into the controlled 452-record score.

The [Sprint 37 final acceptance audit](docs/SPRINT_37.md) is fail-closed:
**458 Python tests, 19 frontend tests and the build pass**, and the functional
SIH prototype is verified, but fresh-source evidence is **not complete**.
The DGA and measured TLS-positive gates fail; `scripts/check_sih_final_gate.py`
returns nonzero and does not promote a new release. This is the current honest
SIH readiness status, separate from the older controlled-demo release below.

The problem statement's dataset field names **traffic generators and public DGA
samples**, not one downloadable benchmark that trains all six detectors. The
visible field ends mid-sentence after “Feature extraction: Extract flow”; we do
not infer requirements from its missing continuation. The table distinguishes
traffic **actually generated/captured** from offline metadata analogues and
research-only domain corpora.

| PS guidance / input | What we actually used | Purpose and exact evidence boundary |
| --- | --- | --- |
| Benign `iperf3`, Ostinato or TRex | `iperf3` 3.16 ran on WSL loopback; **Ostinato and TRex were not run**. | `scripts/generate_sih_tool_capture.sh` → local PCAP → Zeek → `examples/sih26145_tool_capture_zeek_v1.jsonl` (45 records). This proves passive ingestion, **not** benign-class accuracy. See `data/manifests/sih26145-input-compliance-v1.json`. |
| `hping3` SYN/UDP traffic | `hping3` 3.0.0-alpha-2 generated controlled SYN and UDP packets on the same loopback capture. | The same 45-record Zeek fixture verifies the packet-to-metadata-to-upload path. It is **not** a labelled, representative SYN-flood or UDP-reflection accuracy test. |
| Slowloris / slow HTTP exhaustion | `slowhttptest` 1.9.0 ran in its Slowloris/slow-header mode; the separate Slowloris executable was **not** run. | `scripts/generate_sprint34_real_tool_capture.sh` → isolated private-link PCAP → Zeek → `examples/sih26145_real_tools_v1.jsonl`; the Slow HTTP finding is measured from long-lived, low-byte connections. |
| `dnscat2` or iodine DNS tunnel | iodine 0.7.0 established a TXT-based tunnel and carried a successful ping; **dnscat2 was not run**. | The same Sprint 34 capture produced 52 native Zeek DNS transactions; the actual upload path emitted a DNS-tunnelling finding. |
| Published DGA algorithms / DGArchive | **DGArchive was not used.** The bundled `examples/dns_training_demo.csv` trains only the small deployed demonstration n-gram model. Separately, public **UMUDGA** domains were used for guarded DGA research training/validation/final tests, and independent **ExtraHop** domains were used only to test a frozen research candidate. | UMUDGA and ExtraHop research candidates failed promotion gates and **did not replace** the demonstration model. ExtraHop's 40,000-domain evaluation reached 63.36% recall and 6.80% FPR; see `docs/SPRINT_11.md`, `docs/SPRINT_28.md`, `docs/SPRINT_29.md` and `docs/SPRINT_30.md`. No public-domain result is claimed as production accuracy. |
| Sandboxed C2 emulator | `scripts/lab_c2_emulator.py` generated eleven real TCP callbacks about three seconds apart inside the isolated Sprint 34 lab; it is a **timing emulator, not malware or a full C2 framework**. | Native Zeek connection records gave a periodic-beacon finding. A separate jittered, variable-size health-check capture stayed alert-free. Both enter the 141-record actual upload replay. |

Before those real-tool captures, `scripts/build_sih_lab_corpus.py` created a
**different**, deterministic 392-record offline corpus with semantic equivalents
for the PS examples. Its separate ground-truth sidecars are used only **after
inference** to score detector behaviour; that corpus is not a claim that the
named tools were executed. The 452-record mixed and 153-record identity-separated
replays are likewise controlled evaluation fixtures, not model-training data or
proof of universal accuracy. The external CTU-13 flow evaluation is an additional
independent check that exposed botnet-detection gaps, not a passing accuracy claim.
See [Sprint 20](docs/SPRINT_20.md), [Sprint 31](docs/SPRINT_31.md),
[Sprint 34](docs/SPRINT_34.md) and the [requirement audit](docs/SIH26145_REQUIREMENT_GAP_ANALYSIS.md).

The feature-extraction path is: **PCAP / collector-decoded flow export / Zeek log
→ read-only normalization → flow, DNS and TLS/QUIC metadata features → stateful
detectors → structured alerts → dashboard**. Flow features include time, endpoints,
ports, protocol, connection state, duration, bytes and packets; detectors then
derive rates, source-IP entropy, fan-out, inter-arrival variation and volume
ratios. DNS contributes query names/types/length/entropy, while encrypted-session
analysis uses available fingerprints and packet-size/timing observations without
decrypting payloads. See [ingestion and validation](docs/INGESTION_AND_VALIDATION.md)
and [models and features](docs/MODELS_AND_FEATURES.md). NetFlow/IPFIX/sFlow support
means **collector-decoded JSON/NDJSON**, not raw exporter wire decoding.

Sprint 34 adds [isolated real-tool evidence](docs/SPRINT_34.md): an actual
`slowhttptest` Slowloris-mode run, an established iodine DNS tunnel carrying ping,
eleven deterministic C2-timing callbacks and a jittered health-check control are
captured with tcpdump and converted by Zeek 8.0.10. The 141-record actual upload
replay is healthy and produces exactly Slow HTTP, C2 and DNS-tunnel findings while
the benign health source remains alert-free. Raw PCAPs remain local and gitignored.

Sprint 33 freezes the [final SIH submission release](docs/SPRINT_33.md) as
`drastha-sih-v1.0`. Its checksum-pinned manifest and executable acceptance check
cover the current HTTP upload path, both eight-behaviour replays, lab controls,
input formats, passive-safety contract, evidence persistence and demonstrated
50 records/second target. The release is submission-demo ready, not production
ready; its exclusions are explicit and machine-readable.

Sprint 32 adds the [final SIH threat and evidence validation](docs/SPRINT_32.md).
Two independent HTTP-upload replays, SQLite persistence, saved-run snapshots,
incident evidence readback, SIEM export and incremental SSE are checked together.
The 452-record result remains 8 TP / 0 FP / 0 FN / 86 TN with healthy quality;
every subtype now has a presentation-ready SIH threat class and every replay
exposes its passive/read-only safety contract.

Sprint 31 adds [SIH input-format and dataset provenance closure](docs/SPRINT_31.md).
Collector-decoded NetFlow, IPFIX and sFlow JSON/NDJSON now enter the same quality,
detection, correlation and dashboard path as Zeek records. A local-only
iperf3/hping3 PCAP was captured with tcpdump and converted by Zeek 8.0.10 into a
checksum-pinned 45-record healthy replay. Raw binary flow datagrams and broad
vendor interoperability are explicitly not claimed.

Sprint 25 adds the [checksum-pinned final SIH prototype acceptance bundle](docs/SPRINT_25.md).
One command verifies ten evidence/configuration artifacts and reruns the actual
upload replay, contextual hardening, public alert schema, deployment and
performance gates. The machine-readable result is submission-demo ready and
explicitly not production ready.

Sprint 26 adds a [deterministic prepared-host demo bundle](docs/SPRINT_26.md) with
per-file SHA-256 verification and an isolated-directory acceptance rehearsal. It
includes the compiled dashboard but deliberately excludes runtimes, dependencies,
credentials, databases and packet captures; it is not a self-contained installer.

Sprint 27 adds [safe loopback demo startup](docs/SPRINT_27.md). Port conflicts are
detected before `--fresh` can reset the demo database, an available alternative is
suggested, and the exact pre-bound listener is handed to Uvicorn. Start on another
port with `.\scripts\start-demo.ps1 -Port 8001`.

Sprint 28 adds an [independent DGA family holdout and fail-closed promotion
gate](docs/SPRINT_28.md). A predeclared n-gram/lexical hybrid passed validation but
failed final-holdout recall (34.50%, including 20.37% on Vawtrak), so promotion is
correctly rejected. Exact upload parity and healthy quality confirm a model
generalization gap, not an ingestion issue; the deployed demo model is unchanged.

Sprint 29 adds [family-blocked hashed-logistic DGA development](docs/SPRINT_29.md).
All UMUDGA families have now been inspected, so the 87,829-domain three-fold result
is deliberately non-promotable. No tested threshold satisfies the unchanged FPR,
pooled-recall and per-family gates together; a different external or future
environment dataset is required before another final promotion attempt.

Sprint 30 adds an [independent ExtraHop DGA evaluation](docs/SPRINT_30.md). The
full checksum-pinned source is streamed into a deterministic 20k benign / 20k DGA
sample after excluding UMUDGA overlaps. Direct and bounded upload-path predictions
match exactly with healthy quality, but 63.36% recall and 6.80% FPR fail the frozen
gates. Missing publisher TLD/family metadata also keeps promotion blocked.

Sprint 19 adds a real offline Zeek 8.0.10 sensor proof: a deterministic mixed
SYN/DNS/TLS PCAP produces native `conn.log`, `dns.log`, and `ssl.log`, then passes
through shared analysis and dashboard API readback with healthy quality, no
rejections, no detector network connection attempts, and no payload decryption.
See [the exact result and limitations](docs/SPRINT_19.md). This does not claim a
live mirror, QUIC interoperability, real-traffic accuracy or sustained capacity.

Sprint 20 adds a [reproducible SIH-guided offline lab corpus](docs/SPRINT_20.md):
13 isolated checksum-pinned scenarios, 392 chronological records, independent
ground-truth sidecars and an honest shared-pipeline baseline. No attack tool or
live network transmission is used.

Sprint 24 adds a [signed sustained mixed-protocol measurement](docs/SPRINT_24.md).
The shared continuous path passes every gate at 50 records/sec for 60 seconds;
two 100 records/sec attempts remain failed evidence because their maximum producer
lag exceeded 100 ms.

Sprint 23 adds a [fail-closed deployment and confidence contract](docs/SPRINT_23.md):
explicit monitored CIDRs, checksum-linked context policy, passive safety flags,
and machine-readable disclosure that detector confidence is a heuristic evidence
score rather than a calibrated attack probability.

Sprint 22 adds [contextual false-positive hardening and passive Slow HTTP
coverage](docs/SPRINT_22.md). On the 392-record SIH lab corpus, the shared path
produces 9 TP / 0 FP / 0 FN / 5 TN with checksum-pinned operator context while
preserving a counterfactual empty-context run. This is a small synthetic lab
result, not a production accuracy claim.

Sprint 21 adds a [strictly separated DGA research iteration](docs/SPRINT_21.md)
using 24 training, four validation and four previously unseen final-test families.
The frozen candidate failed validation uncertainty and final-holdout
generalization gates, so production loading remains blocked.

Latest verified baseline (10 September 2026): **454 Python tests**, **18 frontend
tests**, and a successful dashboard production build. The corrected accuracy
replay produces **8 findings, 8 incidents, 0 false-positive behaviours and healthy
input quality**. These are controlled synthetic results, not production accuracy.

The corrected 8-threat/false-positive evaluation fixture is the native replay
[`examples/drastha_accuracy_fp_test_v2.jsonl`](examples/drastha_accuracy_fp_test_v2.jsonl),
with an equivalent JSON container beside it, assumptions in the adjacent manifest,
and a reproducible upload-API check
in `scripts/check_accuracy_fixture.py`. It preserves all 53 supplied scenario
records and adds 100 prior passive TLS sessions required by the unchanged feature
extractor; do not describe its synthetic behaviour-level score as production accuracy.

Sprint 17 adds [coordinated journal/analyst backup and same-engine recovery](docs/SPRINT_17.md).
The operator tools validate a signed recovery point, reconstruct detection state
on disposable copies, and preserve the selected analyst reviews and holds.
Original source identity is required; cross-version migration and automatic
cutover remain unsupported. Follow the [recovery runbook](docs/OPERATIONS_RUNBOOK.md#8-coordinated-stream-recovery-sprint-17).

Sprint 18 adds [completed-replay SIEM export](docs/SPRINT_18.md): JSON/NDJSON
downloads with stable import identities, saved-run evidence, telemetry quality,
overall risk and signed-store receipts. In **Review full evidence**, select
**Download SIEM NDJSON**. See the documented import contract before configuring
an external importer; automated delivery and vendor-specific mappings remain open.

Sprint 16 adds [atomic continuous-ingest publication and measured optimization](docs/SPRINT_16.md)
while retaining full source and signed-evidence verification. The finite profiler
run is about 23% faster; both 1,000 records/sec experiments still fail at least one
strict load gate. Defaults and detectors are unchanged, and old checkpoints still
refuse an engine mismatch. This is not a production-capacity claim.

Sprint 15 adds [protected local startup and verified SQLite recovery](docs/SPRINT_15.md).
Use the [operator runbook](docs/OPERATIONS_RUNBOOK.md) for preflight, create-only
backup/restore and manual cutover. This is a loopback-only staged deployment path,
not a replacement for the demo Docker setup or a production-readiness certificate.

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

- [SIH26145 dataset and traffic-tool provenance](#sih26145-dataset-and-traffic-tool-provenance)
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
| UDP reflection/amplification | Response-volume and service-pattern analysis | Direction, packet volume and response pattern |
| DGA-like domain | Character 3-gram Naive Bayes ML model | Uncalibrated model score, domain and entropy context |
| DNS tunnelling | Volume and entropy analysis | Query count, unique labels, length and entropy |
| C2-style callback | Statistical timing analysis | Interval consistency, size consistency and connection count |
| Encrypted-session metadata anomaly | Passive fingerprint and sequence baselines | JA3/JA4 prevalence, measured packet-size and timing anomalies |
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

Uploaded replays also receive an **overall replay risk** across their incidents:
highest incident risk + capped incident-breadth bonus + capped threat-diversity
bonus, limited to 100. The corrected accuracy fixture scores **88/100 (critical)**:
58 + 15 + 15. This policy score is an investigation priority; it does not establish
that separate incidents belong to one coordinated attack. The full calculation
is documented in [Models and features](docs/MODELS_AND_FEATURES.md#overall-replay-risk).

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

Click **Open scored intelligence** to see a recorded incident conclusion: the
observed behaviour, likely objective, attack stage, potential impact, evidence
basis and analytical uncertainty. The same view then separates the detection
timeline, raw supporting measurements and priority-score calculation. Because
Drastha is passive, it reports intent as an evidence-backed hypothesis rather
than a proven fact.

### Instant attack replay

Use **Run instant replay** when you need a shorter demonstration. It runs the C2
and exfiltration attack story immediately and stores one correlated incident.

### Analyst workflow

Open an incident to:

- change the status;
- record a malicious, benign or needs-review decision;
- add investigation notes;
- review the recorded likely objective and its uncertainty;
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

Completed analysis snapshots, findings, incidents and supporting evidence are
stored in the configured analyst database (`output/drastha.db` by default for
SQLite). **Review full evidence** and **Review this incident** use the selected
replay snapshot, so evidence from another upload is not substituted. Exports
include the recorded conclusion, likely objective and uncertainty.

### Reproduce the eight-threat accuracy test

Upload **`examples/drastha_accuracy_fp_test_v2.jsonl`**. This is different from the
original `drastha_accuracy_fp_test.jsonl` draft, whose invalid timestamps and
incomplete DNS/TLS evidence can produce only five incidents. The corrected fixture
preserves 53 scenario records and adds 100 passive TLS baseline observations.

```powershell
.\.venv\Scripts\python.exe scripts/check_accuracy_fixture.py --fixture examples/drastha_accuracy_fp_test_v2.jsonl --report-output output/accuracy-check-new.json
```

Choose a new report filename each time. This check calls the actual upload API in
a temporary database and verifies saved-run readback.

| Measurement | Corrected fixture |
|---|---:|
| Received / accepted / rejected | 153 / 153 / 0 |
| Findings / incidents | 8 / 8 |
| Behaviour-level TP / FP / FN / TN | 8 / 0 / 0 / 107 |
| Precision / recall / F1 | 100% / 100% / 100% |
| Timestamp regressions / duplicate UIDs | 0 / 0 |
| Data quality | healthy |
| Overall investigation priority | 88/100, critical |

Health checks, approved backups and authorized scanners remain benign under the
operator-owned context policy. The 100 baseline encrypted sessions have
insufficient evidence while warming up; four suspicious sessions receive measured
features. The dashboard displays detected, context-suppressed, insufficient and
rejected outcomes separately.

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

The verified Sprint 19 setup uses Ubuntu 24.04 WSL and Zeek 8.0.10 at
`/opt/zeek/bin/zeek`. Before analysing an operator capture, reproduce the
create-only offline sensor check with a new report filename:

```powershell
.venv\Scripts\python.exe scripts\check_sensor_integration.py `
  --mode wsl --distribution Ubuntu-24.04 `
  --report-output output\sensor-check.json
```

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
The Zeek output directory must be new or empty; Drastha refuses to overwrite or
mix existing evidence.

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

The verified baseline contains 390 Python tests covering ingestion,
detectors, ML training, correlation, persistence, API workflows, replay upload,
near-real-time streaming, telemetry quality, PCAP integration and restart
behaviour.

Frontend regression tests and build:

```powershell
cd web
node --test tests/*.test.mjs
pnpm run build
cd ..
```

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
- `/api/analysis-runs/{run_id}` — saved replay report;
- `/api/analysis-runs/{run_id}/export?format=ndjson` — completed-run SIEM export (JSON also supported);
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

- real-sensor validation and seamless log rotation beyond the bounded file follower;
- representative licensed datasets and environment-specific calibration;
- independently measured false-positive and false-negative rates per threat family;
- state compaction, multi-sensor ordering and cross-version checkpoint migration;
- passing sustained 1,000-records/sec gates and longer all-protocol load tests;
- SSO/MFA and credential lifecycle beyond existing opt-in role-based access;
- encrypted/offsite storage, key rotation and external audit-head custody;
- service supervision, high availability and upgrades beyond same-engine recovery;
- SIEM/SOAR integration and operational governance.

Signed 100-records/sec runs passed. Recent 1,000-records/sec, batch-256 runs
processed 60,000 records with healthy quality but still failed the unchanged
100 ms producer-scheduling gate. The higher target remains unproven.

See
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

- [SIEM export contract and validation (Sprint 18)](docs/SPRINT_18.md)
- [Coordinated same-engine recovery (Sprint 17)](docs/SPRINT_17.md)
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
