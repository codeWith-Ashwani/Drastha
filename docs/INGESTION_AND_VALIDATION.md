# Replay ingestion and validation

Drastha treats every replay as read-only passive telemetry. Validation never
opens a network connection, resolves an observed name, completes a handshake,
decrypts a payload, or sends a mitigation command.

## Processing boundary

The replay path is:

1. `api.py` accepts the local upload body and maps validation failures to HTTP
   422.
2. `replay_input.py` identifies JSONL/NDJSON, JSON arrays, wrapped `records`
   arrays, or a single JSON object while retaining line/record locations.
3. `zeek_jsonl.py` resolves only the documented, unambiguous field aliases into
   a canonical Zeek-shaped record. Conflicting aliases are rejected.
4. The record schema is classified as connection, DNS, TLS, or QUIC from
   explicit metadata. DNS records are not also treated as connection records.
5. The connection, DNS, and encrypted-session normalizers validate required
   fields and create the immutable internal event models in `models.py`.
6. `upload_analysis.py` quarantines malformed records, tracks original input
   ordering and duplicate UIDs, then sorts accepted events only for detector
   processing.
7. Detectors, correlation, persistence, the API response and dashboard consume
   canonical events and structured quality results.

PCAP ingestion remains separate: `zeek_runner.py` invokes a local Zeek process
and its generated logs enter the same Zeek normalizers. Simulated streams and
CLI replays also use those normalizers.

## Required connection fields and aliases

| Canonical field | Accepted aliases |
| --- | --- |
| `ts` | `timestamp`, `time`, `@timestamp` |
| `uid` | `flow_id`, `flowid` |
| `id.orig_h` | `src_ip`, `src`, `source_ip`, `source.address` |
| `id.orig_p` | `src_port`, `source_port`, `source.port` |
| `id.resp_h` | `dst_ip`, `dst`, `destination_ip`, `destination.address` |
| `id.resp_p` | `dst_port`, `destination_port`, `destination.port` |
| `proto` | `protocol`, `network.transport` |

Ports are optional and default to zero when absent. Addresses accept valid IPv4
and IPv6. Timestamps accept Unix seconds and ISO-8601, including timezone-aware
values. Unknown fields and useful Zeek optional fields remain available in the
raw canonical record.

## Error origins

- Container/JSON structure errors originate in `replay_input.py` and name the
  input line or supported containers.
- Missing fields, conflicting aliases, invalid timestamps, addresses, ports and
  protocols originate in `zeek_jsonl.py`.
- DNS query/answer errors originate in `zeek_dns.py`.
- TLS/QUIC metadata errors originate in `zeek_encrypted.py`.
- File-level unusable decisions originate in `upload_analysis.py` after all
  safe records have been attempted.

Each rejected record has a line number, reason, field, safe value when useful,
and error category. Rejected records are counted as quarantined; they are never
silently discarded. Up to 10% rejected telemetry is degraded. More than 10%,
or no accepted records, is unusable. Timestamp regressions and duplicate UIDs
are visible and degrade quality without being hidden by detector-side sorting.

## Validator

```powershell
python -m aegisflow.validate_replay examples/drastha_mixed_evaluation_v3.jsonl
drastha validate-replay --input examples/drastha_mixed_evaluation_v3.jsonl
```

Both commands are passive and use a no-op persistence sink.
