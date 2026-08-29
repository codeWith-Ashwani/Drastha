# AegisFlow

AegisFlow is a passive network-security analytics platform for one-way monitoring environments. The codebase is being built as a sequence of testable vertical slices.

The current Sprint 0-3 implementation can:

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

## Current boundaries

- Raw-PCAP execution requires an external Zeek installation; the adapter fails clearly when it is absent.
- Reconnaissance, initial DDoS, DNS, and C2 beacon detectors are implemented; exfiltration and cross-detector correlation are later sprints.
- The DNS model is trained on a tiny synthetic fixture to verify the pipeline. Production claims require licensed, versioned datasets and deployment-specific calibration.
- DNS-over-HTTPS is not visible from ordinary Zeek DNS logs unless telemetry is collected before encryption.
- Confidence is a transparent heuristic pending calibration on labelled data.
- Severity is policy-based and does not claim operational impact knowledge.
- The sample thresholds and seven-event throughput figure are smoke-test values, not production benchmarks.

See [docs/STATUS.md](docs/STATUS.md) for current progress and [docs/SPRINTS.md](docs/SPRINTS.md) for the full implementation plan and acceptance criteria.
