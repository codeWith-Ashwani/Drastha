# Sprint 36 — fresh SIH-source validation, with failures retained

This is a **new** Gate 2 session, not another measurement of the 452-record
synthetic replay. All traffic was confined to a private WSL network namespace
without a default route. TCP/UDP traffic was passively captured with tcpdump,
decoded with Zeek, and submitted to the actual upload-analysis API. No detector
sent a probe to an observed endpoint. Raw PCAPs and publisher files remain local
and gitignored; committed derived fixtures, independent label sidecars, generator
scripts and SHA-256 freeze manifests identify exactly what was analysed. Neither
ground-truth labels nor anomaly scores were inserted into replay records.

| Source and test | Records / sessions | Observed result | Boundary |
| --- | ---: | --- | --- |
| `iperf3` low load, `hping3` SYN and port fan-out, `hping3` UDP, valid UDP lab responder, `iperf3` bulk transfer | 768 Zeek records in 6 separate scenarios | 5/5 expected behaviours found, 0 unexpected behaviours, 1/1 modest-load benign control clear; all accepted, quality healthy | UDP response shape does not prove source spoofing or third-party reflection. Bulk asymmetry does not prove theft. |
| `slowhttptest` Slowloris mode, isolated C2 timing emulator, iodine tunnel carrying ping | 136 Zeek records in 3 separate scenarios | 3/3 expected behaviours found, 0 unexpected; all accepted, quality healthy | These are lab behaviours, not identified malware or demonstrated service outage. |
| Public UMUDGA Vawtrak v3 and `legit-test` domains | 40 DGA + 40 benign DNS-like records | **0 TP, 40 FN, 2 FP, 38 TN**; all accepted, quality healthy | The deployed demo n-gram model generalizes poorly to this wordlike family. Publisher samples were inspected in earlier research, so this is not a virgin family holdout. No DNS query was transmitted. |
| Real OpenSSL TLS 1.2 baseline / TLS 1.3 changed sessions | 110 baseline + 6 changed, 232 Zeek records | **0 anomaly alerts, 6 changed-session misses, 0 benign false alerts**; all accepted, quality healthy | PCAP-derived JA3/size/timing features only. The changed handshakes had rare fingerprints but normal first-eight-packet size/timing; they are not malware. 100/116 sessions lacked enough preceding baseline history for full derived scoring. |

The flow and metadata labels were frozen before inference. The TLS raw capture,
source-port identity mapping and v1 native Zeek log were frozen before inference;
the v1 mixed `ssl.log` rows lacked an explicit record-kind hint. A v2 adapter adds
only `transport: tls` to those rows, leaving all packet evidence and labels
unchanged. The v1 import failure is retained, not erased. TLS scoring used the
real PCAP attachment path with `DEPLOYMENT_BASELINE`; no supplied compatibility
features, decryption or injected probabilities were used. The measured-only
audit reports 16 fully derived sessions and 100 insufficient-evidence sessions.

Scripts: `generate_sih_gate2_*_capture.sh`, `freeze_sih_gate2_*.py`,
`check_sih_gate2_*.py`. Machine-readable results:
`output/sih_gate2_{flow,metadata,dga,tls}_audit.json`. Portable frozen-file
regression checks live in `tests/test_sih_gate2_frozen.py`. To repeat a *raw*
capture verification or TLS PCAP-enriched evaluation, retain the gitignored
`data/raw/sih26145-gate2-*` directories or generate a distinct new capture ID;
the committed repo alone can verify derived fixture hashes but does not contain
the binary PCAPs or TLS private key.

Gate 2 conclusion: fresh PS-tool integration passes for the captured flow,
Slow HTTP, C2 and iodine scenarios. **Independent DGA generalization and a
measured encrypted-session anomaly demonstration do not pass.** No detector
threshold, quality rule or label was changed to hide either result.
