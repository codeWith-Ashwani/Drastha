# AegisFlow build status

Last updated: 29 August 2026

## Overall

- Sprint 0: complete
- Sprint 1: complete; real PCAP processed through Zeek 8.0.10 in WSL
- Sprint 2: demonstrable prototype complete; production dataset calibration remains future work
- Sprint 3: demonstrable prototype complete; CTU-13 holdout acquisition remains future work
- Sprints 4-7: planned

## Sprint 0 acceptance checklist

- [x] Python package and repository structure
- [x] Shared `NetworkEvent`, `Evidence` and `Alert` contracts
- [x] Zeek `conn.log` JSONL parsing and normalization
- [x] Line-numbered validation errors
- [x] Vertical port-scan detection
- [x] Horizontal host-scan detection
- [x] Sliding-window expiry
- [x] Alert cooldown/deduplication
- [x] Confidence, severity, flow IDs, evidence and limitations
- [x] Command-line replay
- [x] Synthetic scan fixture
- [x] Seven automated tests passing
- [x] Saved end-to-end demo alert

## Verified commands

```powershell
python -m unittest discover -s tests -v
$env:PYTHONPATH = "src"
python -m aegisflow.cli replay --input examples/zeek_conn_scan.jsonl --port-threshold 5 --host-threshold 5
```

## Current limitations

- Zeek JSONL replay and raw-PCAP processing are fully verified. The real sample capture produced 12 normalized connection events through the Windows-to-WSL adapter.
- Reconnaissance, SYN-flood and UDP-flood behaviour are implemented. UDP reflection/amplification attribution still needs service-aware directional features.
- Thresholds are configuration values, not yet learned from a benign baseline.
- Confidence is transparent but not calibrated on labelled datasets yet.
- There is no API, database or dashboard yet.

## Sprint 1 acceptance checklist

- [x] Reusable keyed sliding-window engine
- [x] Bounded out-of-order event support
- [x] SYN-flood detector with incomplete-connection ratio
- [x] UDP-flood detector using packet and byte volume
- [x] Separate evidence and limitations per DDoS subtype
- [x] Replay health: count, event span, ordering and processing rate
- [x] Capture-loss visibility reported honestly when unavailable
- [x] PCAP-to-Zeek subprocess adapter
- [x] Zeek availability command and actionable error
- [x] CICDDoS2019 dataset manifest and leakage-safe split policy
- [x] Eighteen total automated tests passing
- [x] Saved Sprint 1 alerts and health report
- [x] Windows-to-WSL Zeek bridge and real Zeek readiness check
- [x] Real PCAP-to-Zeek-to-detectors execution using `/home/shukl/zeek-test/sample.pcap`

## Next sprint

## Sprint 2 acceptance checklist

- [x] Separate Zeek DNS event adapter with line-numbered validation
- [x] Lexical features: length, labels, digits, hyphens, vowels, uniqueness and entropy
- [x] Character 3-gram feature pipeline and inspectable Naive Bayes model
- [x] Duplicate-domain and malicious-family leakage checks
- [x] DNS-tunnelling sliding-window features
- [x] Distinct DGA-like and DNS-tunnelling alert subtypes
- [x] CDN and hosted-service benign holdout examples
- [x] Allowlist support
- [x] Encrypted-DNS limitation in reports and alerts
- [x] Versioned benign-snapshot manifest and synthetic demonstration fixture
- [x] Generated model artifact, metrics and model card
- [x] Synthetic replay: 21 events, 2 expected alerts
- [x] Real sample replay: 7 DNS events, 0 alerts
- [x] Twenty-seven total automated tests passing
- [ ] Production dataset acquisition, licence review and calibration

## Next sprint

## Sprint 3 acceptance checklist

- [x] Per-endpoint repeated-connection windows
- [x] Mean interval, jitter, periodicity and size-consistency features
- [x] Periodic C2-like beacon alert with inspectable evidence
- [x] Zeek TLS and generic QUIC metadata adapter
- [x] Server-name, version, cipher, ALPN and fingerprint context
- [x] Contextual encrypted-session anomaly score
- [x] Fingerprints prohibited as sole alert triggers
- [x] Benign irregular scheduled-traffic and variable-transfer tests
- [x] Destination allowlist support
- [x] CTU-13 scenario-holdout manifest
- [x] Synthetic replay: 8 connections, 8 TLS records, 1 expected alert
- [x] Real sample replay: 12 connections, 2 TLS records, 0 alerts
- [x] Thirty-five total automated tests passing
- [ ] CTU-13 dataset acquisition, licence review, scenario evaluation and calibration

## Next sprint

Sprint 4 will add exfiltration features, incident-level correlation, deterministic
scoring, deduplication, and analyst-feedback structures.
