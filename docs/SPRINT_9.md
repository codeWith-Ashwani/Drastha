# Sprint 9 — measured passive features

Date: 4 September 2026. This sprint implements a measured feature path; it does
not establish production accuracy or remove the need for environment calibration.

## What changed

1. `ingestion/pcap_metadata.py` reads an explicitly selected capture, extracts IP
   packet lengths, originator/responder direction, timestamps and supported JA3
   ClientHello fingerprints. Nothing is sent onto the monitored network.
2. `ingestion/capture_join.py` joins packets to Zeek connections by 5-tuple and
   connection interval, then joins TLS metadata by UID, endpoints and interval.
   Ambiguous matches are counted and not guessed. A complete ClientHello can
   create TLS metadata when an ssl.log record is unavailable.
3. `passive_features.py` computes causal fingerprint prevalence and robust
   sequence anomaly scores from preceding observations. Evaluation labels and
   supplied anomaly scores are not inputs to this derived path.
4. `network_context.py` provides operator-configured network direction for
   exfiltration, including internal response bytes on externally initiated flows.
5. Service-aware UDP reflection groups responses by their recipient (Zeek
   originator), potentially across several responders, and requires recognizable
   UDP service ports and observed nonzero request bytes. SYN attempt-rate evidence
   now always comes from actual normalized records, not supplied rate scores.
6. Causal DNS evidence associates a preceding query with the same flow/endpoints
   or the same client and an answer IP. This adds supporting evidence only; it
   never creates a trusted endpoint, changes a threshold, or performs a DNS query.
7. HTTP results, completed streams, stored run reports and the dashboard expose
   feature coverage. Investigation evidence includes measured scores, supporting
   flow IDs, sequence hashes, extractor version and attached capture hash.
8. Nonfinite record timestamps are rejected instead of entering detector windows.

## Data path and availability

The existing shared upload/stream/file analysis session remains the inference
entry point. JSON uploads can contain monitoring-side `packet_observations`.
The CLI can additionally derive those observations from a local classic PCAP.
Raw PCAP upload through the browser is **not** added by this sprint.

```text
explicitly selected PCAP + Zeek connection records
  -> header/ClientHello extraction -> tuple/time join -> typed TLS metadata
  -> shared AnalysisSession -> prior-history features -> detector
  -> findings/incidents -> stored report/API -> dashboard/evidence
```

Packet observations are retained in capture order. The original replay's quality
is checked before detector sorting; attaching a capture cannot clear degraded
quality. Capture reordering, snap-length truncation, ambiguous packets and
conflicting ClientHellos add separate quality reasons. Unsupported protocols,
unmatched packets and incomplete handshakes are counted in
`input_schema.packet_capture.counters`, not converted into invented features.

Derived metadata is timestamped at the latest retained packet or fingerprint
observation, whichever is later, and retains the original metadata timestamp.
This prevents evidence becoming available retrospectively at connection start.
Consequently, a connection emitted earlier does not receive future TLS context.
Existing start-time Zeek records are not rewritten or relabelled.

## Capture support and limits

Supported: classic PCAP v2.4, little/big endian, micro/nanosecond timestamp
resolution, Ethernet with optional VLAN tags, IPv4 and basic IPv6, TCP/UDP.
JA3 requires a complete cleartext ClientHello in one TCP segment. The algorithm
uses ClientHello version, cipher suites, extensions, groups and point formats,
excluding GREASE values, following the [Salesforce JA3 specification](https://github.com/salesforce/ja3).
MD5 is the prescribed JA3 identifier, **not** an integrity/security signature.
Capture and sequence identities use SHA-256, which alone is not a signed chain
of custody.

Not implemented: TCP reassembly, PCAPNG, non-Ethernet link types, fragmented IP,
IPv6 extension chains/jumbograms, JA3S extraction, native JA4 computation or QUIC
fingerprint extraction. Existing JA4/JA3S metadata from a trusted monitoring-side
sensor is accepted without claiming Drastha computed it. JA3 and JA4 populations
are kept in separate cohorts. Application payload bytes are not returned or
persisted by this extractor. No TLS payload decryption is performed.

The reader rejects malformed capture containers and enforces a 5,000,000-packet
limit. At most the first 128 packet observations per matched flow are retained;
discarded tails are counted. This is a finite offline adapter, not an unbounded
packet-stream receiver. Capture timestamps must share the Zeek sensor's clock.
IP/TCP checksums are not verified; retransmissions are not collapsed.

## Feature definitions and cold start

For each service cohort (sensor ID, transport, responder port, application
protocol, fingerprint family), the extractor keeps at most 5,000 prior sessions
within 3,600 seconds. At most 128 cohorts are retained with least-recently-used
eviction. Independent replay sessions never share learned state.

- Sequence: first up to 8 IP lengths, signed positive for originator and negative
  for responder, plus adjacent timestamp differences. Minimum 4 packets.
- Reference: at least 20 preceding comparable sequence samples. For each
  position, calculate the reference median and median absolute deviation (MAD).
- Position deviation: `abs(value - median) / max(1.4826 * MAD, scale_floor)`.
  Floors are 32 bytes and 0.001 seconds. The median position deviation divided
  by 6 is clipped to [0,1], separately for size and timing.
- Fingerprint prevalence: prior occurrences / prior fingerprint-bearing sessions,
  requiring at least 100 prior sessions. The current sample is excluded.
- Baseline update occurs after scoring. Once scores exist, sequences at or above
  0.75 in either dimension are excluded from sequence-baseline learning. They
  still count toward fingerprint population statistics. Duplicate session IDs
  within a cohort/history do not inflate warm-up or prevalence.

This is online **unsupervised statistical feature estimation**, not a supervised
malware classifier. Initial history is observational, not verified benign;
poisoning, drift, collection gaps and changing applications remain risks.
Derived scores and detector confidence are not calibrated attack probabilities.
The existing DNS n-gram model is unchanged.

The encrypted detector's thresholds are unchanged: at least 4 repeated sessions
in 60 seconds, average prevalence <= 0.01, size and timing scores >= 0.75. A
fingerprint alone never proves malware. Findings remain labelled
**Encrypted-session metadata anomaly**.

Warm-up, absent fingerprint, malformed/future-dated sequences, missing packet
data and insufficient position coverage result in `insufficient_evidence`, not
zero anomaly scores. Coverage remains distinct from telemetry quality: valid
records can be healthy while providing too little evidence for a detector.

## Compatibility and operator configuration

`upload-demo` and `stream-demo` preserve existing demonstration fixtures, allowing
complete valid supplied scores only when no packet sequence is supplied. Such
results are explicitly `supplied_compatibility`, never described as measured.
A supplied invalid sequence cannot fall back to canned scores.

`deployment-baseline` uses derived features only, service-aware reflection and
explicit network boundaries. Thresholds are **uncalibrated**, not production
defaults validated on independent traffic. Choose it through the CLI profile
option or `DRASTHA_ANALYSIS_PROFILE` for HTTP/stream routes.

```powershell
$env:DRASTHA_ANALYSIS_PROFILE = "deployment-baseline"
$env:DRASTHA_INTERNAL_NETWORKS = "10.20.0.0/16,2001:db8:20::/48"
.venv\Scripts\python.exe -m aegisflow.cli analyse --input .\zeek-logs --packet-capture .\traffic.pcap --profile deployment-baseline --report-output .\output\capture-report.json
```

Use actual monitored CIDRs, not the example values. Invalid CIDRs fail explicitly.
Unconfigured boundaries in derived mode disable exfiltration evaluation with an
explicit `unconfigured` coverage status; private addressing is not guessed to be
the monitored network. Internal-to-internal and external-to-external traffic is
not called outbound exfiltration. Compatibility mode without CIDRs retains the
historical Zeek-originator byte view.

Externally initiated connections are reversed **only** for exfiltration's view:
internal sender, external recipient, corresponding ports and byte/packet counts.
Other detectors retain Zeek initiator semantics. Approved bulk-transfer rules
must match this view; for externally initiated requests the external recipient
port can be ephemeral. No automatic approval is inferred from a DNS name.

`pcap --all-threats --packet-features` attaches its explicitly supplied input
PCAP after Zeek conversion. Without `--packet-features`, prior PCAP-log analysis
behaviour remains available. Unsupported captures fail extraction explicitly;
there is no silent switch to supplied scores.

Monitoring-side JSON sequence contract (record `ts` is availability time):

```json
{"ts":1000.3,"uid":"TLS1","transport":"tls","id.orig_h":"10.20.0.2","id.resp_h":"198.51.100.8","id.resp_p":443,"ja3":"sensor-computed-fingerprint","packet_observations":[{"ts":1000.0,"ip_bytes":120,"direction":"orig"},{"ts":1000.1,"ip_bytes":400,"direction":"resp"},{"ts":1000.2,"ip_bytes":80,"direction":"orig"},{"ts":1000.3,"ip_bytes":90,"direction":"resp"}]}
```

Imported packet metadata is only as trustworthy as its sensor and transport;
this sprint does not add source authentication. DNS context uses at most 10,000
prior records / 60 seconds and returns at most 20 associations. The association
window is not an authoritative DNS TTL or a reputation signal.

## Verification

The new tests generate binary captures locally in temporary directories. No
private traffic or raw captures are committed. Controlled capture acceptance
uses 400 ordinary sessions followed by 4 anomalous sessions, without supplied
anomaly scores: 1,616 packets matched, 404 records accepted, one encrypted-session
finding, healthy telemetry, and capture bytes unchanged. The same CLI shared
analysis service persists evidence; separate actual FastAPI upload and streamed
replay tests verify derived metadata/report parity and SQLite persistence.

Regression coverage includes GREASE, endian/timestamp formats, VLAN/IPv6,
ambiguous joins, missing and invalid evidence, late ClientHellos, capture ordering,
malformed captures, duplicate sessions, expiry, cohort isolation, causal DNS
context, inbound response exfiltration and UDP service/recipient grouping.

The 452-record mixed fixture remains unchanged, with 8 findings / 8 incidents /
8 TP / 0 FP / 0 FN / 86 TN and healthy quality under its demonstration profile.
These are behaviour-level fixture metrics, not a production accuracy estimate.

Verification on 4 September 2026:

- `.venv\Scripts\python.exe -m unittest discover -s tests -v`: **168 tests passed**
  (142 existing and 26 new), 4.456 seconds on this run.
- `.venv\Scripts\python.exe -m unittest tests.test_mixed_evaluation_replay -v`:
  passed separately, including the actual upload-analysis path and exact metrics.
- `pnpm run build` in `web`: TypeScript and Vite build passed.
- `git diff --check`: passed. Existing Starlette/httpx deprecation warning remains
  non-failing.

No live Zeek installation, live PostgreSQL server or sustained production-rate
capture test is claimed for this sprint. Dashboard coverage was build-verified;
no browser visual inspection was performed in this sprint.

## Remaining production work

Independent datasets and held-out calibration (Sprints 10–11); durable continuous
ingestion, backpressure and recovery (12); authentication, retention and signed
evidence (13); sustained end-to-end load and real sensor/browser testing (14);
operational deployment (15). Per-cohort feature state is bounded, but finite
replay preparation and existing detector/result history still scale with input.
