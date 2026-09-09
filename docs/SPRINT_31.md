# Sprint 31 — SIH input-format and dataset provenance closure

## Outcome

Drastha now accepts collector-decoded NetFlow, IPFIX and sFlow JSON/NDJSON
records through the same upload, quality, detector, incident and dashboard path
as Zeek telemetry. The adapter converts exporter field names, IP protocol
numbers, timestamp units, directional counters and duration into the existing
canonical event without discarding the original record. Every converted event
records its format and passive-ingest provenance.

This sprint also adds an actual local-only tool chain: iperf3 and hping3 generate
traffic exclusively on Linux/WSL loopback, tcpdump records a PCAP, and Zeek 8.0.10
converts it into the committed 45-record chronological fixture. The raw 40 MB
PCAP remains under ignored `data/raw/`; its checksum, tool versions, destination
and generation recipe are pinned in the manifest.

## Supported collector contracts

| Export | Important accepted fields | Canonical interpretation |
| --- | --- | --- |
| NetFlow | `srcaddr`, `dstaddr`, `srcport`, `dstport`, `prot`, `dOctets`, `dPkts` | one exported direction plus optional `OUT_*` reverse counters |
| IPFIX | source/destination IPv4 or IPv6 address, transport ports, `protocolIdentifier`, delta/total counters | millisecond/second start time and optional reverse Information Elements |
| sFlow | `srcIP`, `dstIP`, ports, `ipProtocol`, sampled size/count, `samplingRate` | observed sample only; counters are not multiplied by sampling rate |

Missing exporter flow IDs receive a stable content-derived identifier. Identical
records therefore remain visible to the existing duplicate-quality check.
Conflicting aliases, unknown protocol numbers, negative counters and missing or
invalid timestamps fail through the normal quarantine/quality path.

The implementation accepts records already decoded by a passive collector. It
does **not** claim raw NetFlow/IPFIX datagram decoding, sFlow packet decoding or
interoperability with every vendor template. Those require exporter-specific
captures and remain outside the SIH prototype acceptance claim.

## Actual tool-capture evidence

`scripts/generate_sih_tool_capture.sh` is restricted to `127.0.0.1`. It used:

- iperf3 3.16 for benign TCP load;
- hping3 3.0.0-alpha-2 for controlled SYN and UDP packet patterns;
- tcpdump 4.99.4 for loopback capture;
- Zeek 8.0.10 for passive metadata conversion.

`scripts/build_sprint31_capture_fixture.py` sorts Zeek's connection-completion
output by observation timestamp before creating
`examples/sih26145_tool_capture_zeek_v1.jsonl`. The actual upload path accepts all
45 records, rejects zero and reports healthy quality with no duplicate IDs or
timestamp regressions.

The loopback replay currently produces one reconnaissance finding because one
host contacts five observed ports. This is recorded but is not an accuracy
claim: loopback directionality and the combined tool capture are not a labelled
gateway corpus. Threat accuracy remains owned by the separate 452-record mixed
evaluation, which still produces 8 TP, 0 FP, 0 FN, 86 TN, eight findings/eight
incidents and healthy quality.

## Reproduction

Run capture generation only inside the isolated WSL lab:

```bash
sudo bash scripts/generate_sih_tool_capture.sh /mnt/f/Drastha/Drastha
```

Then verify the immutable derived fixture and the complete audit:

```powershell
.venv\Scripts\python.exe scripts\build_sprint31_capture_fixture.py --check
.venv\Scripts\python.exe scripts\check_sprint31_input_compliance.py `
  --report-output output\sprint31_input_compliance_reproduction.json
```

The authoritative manifest is
`data/manifests/sih26145-input-compliance-v1.json`. It distinguishes actual tool
evidence, deterministic format-contract fixtures and unsupported claims.

## Safety and scientific boundaries

- No external or production address is targeted.
- No detector opens a socket, returns traffic, completes a handshake, decrypts
  payload or issues mitigation.
- Uploaded labels still cannot affect inference.
- sFlow sample-rate extrapolation is deliberately avoided.
- Tool-derived traffic proves the ingest chain, not real-world accuracy.
- Raw captures remain excluded from Git to prevent accidental traffic release.

## Regression verification

- Sprint 31/input/mixed/PCAP targeted suite: 37 tests passed.
- Full Python suite: 444 tests passed.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
