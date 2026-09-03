"""Join an explicitly selected passive capture to normalized Zeek flow records."""
from collections import Counter, defaultdict
from dataclasses import replace

from aegisflow.ingestion.pcap_metadata import extract_capture
from aegisflow.models import EncryptedSessionMetadata


def attach_capture(prepared, path):
    capture = extract_capture(path, prepared.events)
    connections = defaultdict(list)
    for event in prepared.events:
        connections[(event.flow_id, event.src_ip, event.dst_ip)].append(event)
    counts = Counter()
    attached = set()

    def enrich(metadata, connection, identity):
        observations = capture.sequences.get(identity, [])
        hello = capture.fingerprints.get(identity)
        raw = dict(metadata.raw)
        raw.update({"packet_observations": observations, "source_metadata_ts": metadata.timestamp,
                    "id.resp_p": connection.dst_port,
                    "capture_provenance": {"capture_sha256": capture.report["capture_sha256"],
                        "extractor_version": capture.report["extractor_version"],
                        "source_flow_id": connection.flow_id, "connection_start": connection.timestamp,
                        "connection_end": connection.timestamp + connection.duration_seconds}})
        if hello:
            raw["observed_ja3"] = hello[1]
            raw["observed_ja3_string"] = hello[0]
        # These features are available only after their last retained packet, not
        # retrospectively at ClientHello/connection start. Never inspect future data.
        timestamp = max([metadata.timestamp, capture.fingerprint_times.get(identity, metadata.timestamp),
                         *(p["ts"] for p in observations)])
        counts["joined_sessions"] += 1
        attached.add(identity)
        return replace(metadata, timestamp=timestamp, raw=raw,
                       client_fingerprint=metadata.client_fingerprint or (hello[1] if hello else ""))

    encrypted = []
    for metadata in prepared.encrypted_events:
        identity = (metadata.flow_id, metadata.src_ip, metadata.dst_ip)
        candidates = [event for event in connections.get(identity, [])
                      if event.timestamp - 0.000001 <= metadata.timestamp <=
                      event.timestamp + event.duration_seconds + 0.000001]
        if len(candidates) == 1:
            encrypted.append(enrich(metadata, candidates[0], identity))
        else:
            counts["unmatched_or_ambiguous_metadata"] += 1
            # Explicit capture request must not silently reuse supplied scores.
            encrypted.append(replace(metadata, raw={**metadata.raw, "packet_observations": []}))
    for identity, hello in capture.fingerprints.items():
        if not hello or identity in attached or len(connections[identity]) != 1:
            continue
        connection = connections[identity][0]
        metadata = EncryptedSessionMetadata(
            timestamp=connection.timestamp, flow_id=connection.flow_id,
            src_ip=connection.src_ip, dst_ip=connection.dst_ip, transport="tls",
            source="pcap:clienthello", raw={"id.resp_p": connection.dst_port})
        encrypted.append(enrich(metadata, connection, identity))
        counts["capture_only_tls_sessions"] += 1
    prepared.encrypted_events = encrypted
    prepared.input_schema = {**prepared.input_schema, "packet_capture": {**capture.report, "join": dict(counts)}}
    # Record capture quality separately; never clear an existing input-quality flag.
    for name in ("out_of_order_packets", "snaplen_truncated_packets", "ambiguous_packets", "conflicting_client_hellos"):
        count = capture.report["counters"].get(name, 0)
        if count:
            if prepared.quality.status == "healthy":
                prepared.quality.status = "degraded"
            prepared.quality.degraded_reasons.append(f"Capture: {count} {name}")
    return prepared
