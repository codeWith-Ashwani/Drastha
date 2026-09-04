"""Build the chronological SIH accuracy/false-positive fixture from its supplied draft."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path


SCENARIOS = {
    "SYN": ("attack", "volumetric_ddos_syn_flood"),
    "UDP": ("attack", "udp_reflection_amplification"),
    "C2": ("attack", "botnet_c2_beaconing"),
    "DGA": ("attack", "dga_domain"),
    "TUN": ("attack", "dns_tunnelling"),
    "TLS": ("attack", "encrypted_session_malware"),
    "REC": ("attack", "reconnaissance_port_scan"),
    "EXF": ("attack", "data_exfiltration"),
    "HC": ("benign", "benign"),
    "BKP": ("benign", "benign"),
    "MSN": ("benign", "benign"),
}


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def packet_sequence(event_time, sizes, interval):
    start = event_time - interval * len(sizes)
    return [{"ts": round(start + interval * index, 6), "ip_bytes": size,
             "direction": "orig" if index % 2 == 0 else "resp"}
            for index, size in enumerate(sizes)]


def load_records(source):
    """Read the supplied draft as JSON, a JSON array, or JSONL/NDJSON."""
    path = Path(source)
    raw = path.read_text(encoding="utf-8-sig")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Line {line_number} must contain one record object")
            records.append(record)
        return records
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return payload["records"]
    raise ValueError("Expected JSONL, a JSON array, or an object containing records")


def build(source):
    records = load_records(source)
    if len(records) != 53:
        raise ValueError("Expected the supplied 53-record draft")
    corrected = {"C22": "2026-09-04T10:03:00Z", "C23": "2026-09-04T10:03:30Z",
                 "C24": "2026-09-04T10:04:00Z", "C25": "2026-09-04T10:04:30Z"}
    # Move later scenarios without changing their relative spacing so the C2
    # sequence remains isolated and the complete fixture is chronological.
    offsets = {"DGA": 120, "TUN": 120, "TLS": 120, "REC": 120, "EXF": 120,
               "HC": 120, "BKP": 120, "MSN": 120}
    tunnel_labels = [
        "a8f3c91d72e4b6f000c7d1e9b5", "b7e2d80c61f5a4e111d6c2f8a4",
        "c6d1e79b50a693f222e5b3a7d3", "d5c0f68a49b582e333f4a296c2",
    ]
    for record in records:
        prefix = next((name for name in SCENARIOS if record["uid"].startswith(name)), None)
        if prefix is None:
            raise ValueError(f"Unknown scenario UID {record['uid']}")
        if record["uid"] in corrected:
            record["ts"] = timestamp(corrected[record["uid"]])
        else:
            value = timestamp(record["ts"])
            record["ts"] = value + offsets.get(prefix, 0)
        label, threat = SCENARIOS[prefix]
        record["evaluation_label"] = label
        record["evaluation_threat_class"] = threat
        record["evaluation_id"] = "SIH-ACC-" + record["uid"]
        if prefix == "TUN":
            index = int(record["uid"][3:])
            record["query"] = tunnel_labels[index] + ".tunnel.example"
        if prefix == "TLS":
            event_time = float(record["ts"])
            record["packet_observations"] = packet_sequence(
                event_time, [1200, 85, 1420, 92, 1310, 78, 1500, 88], .20)
            # Root-level claimed scores from the draft were not consumed and
            # are removed; anomaly values will be derived from packet samples.
            record.pop("packet_size_anomaly", None)
            record.pop("fingerprint_prevalence", None)

    first = min(float(record["ts"]) for record in records)
    baselines = []
    for index in range(100):
        event_time = first - 200 + index
        baselines.append({
            "ts": event_time,
            "uid": f"TLSBASE{index:03d}",
            "id.orig_h": f"192.0.2.{index + 1}",
            "id.resp_h": f"198.19.{index // 250}.{index % 250 + 1}",
            "proto": "udp", "id.orig_p": 40000 + index, "id.resp_p": 443,
            "orig_bytes": 240, "resp_bytes": 320, "conn_state": "SF", "service": "quic",
            "ja4": f"q13d0312h3_baseline_{index % 20:02d}",
            "packet_observations": packet_sequence(event_time, [210, 310, 220, 320, 215, 315, 225, 325], .01),
            "evaluation_label": "benign", "evaluation_threat_class": "benign",
            "evaluation_id": f"SIH-TLS-BASELINE-{index:03d}",
        })
    output = sorted([*baselines, *records], key=lambda record: (float(record["ts"]), record["uid"]))
    if len(output) != 153 or len({r["uid"] for r in output}) != 153:
        raise AssertionError("Fixture record/UID invariant failed")
    return {"fixture": "drastha-accuracy-fp-v2", "source_records": 53,
            "source_invalid_timestamps_corrected": 4,
            "added_passive_tls_baseline_records": 100, "records": output}


def write_fixture(payload, output):
    """Write native JSONL for replay or a metadata-bearing JSON container."""
    path = Path(output)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        path.write_text("".join(json.dumps(record, separators=(",", ":")) + "\n"
                                for record in payload["records"]), encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output exists; choose a new path")
    write_fixture(build(args.source), args.output)
