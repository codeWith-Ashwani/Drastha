"""Offline corpus adapters and auditable labels, separate from detector input."""
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from hashlib import sha256
from ipaddress import ip_address
import io
import json
import math

from aegisflow.benchmark_metrics import CLASSES
from aegisflow.ingestion.passive_replay import prepare_replay
from aegisflow.ingestion.zeek_jsonl import normalize_field_aliases


# Canonical metadata only: no scores, answer keys, policy allowlists or arbitrary
# feature dictionaries from datasets can leak into inference.
TELEMETRY_FIELDS = frozenset("""ts uid id.orig_h id.resp_h id.orig_p id.resp_p proto
duration orig_bytes resp_bytes orig_pkts resp_pkts conn_state history service
query qtype_name qtype rcode_name rcode answers rejected transport
ja3 ja3s ja4 client_fingerprint server_fingerprint server_name version cipher
next_protocol alpn established resumed packet_observations sensor_id""".split())


def clean_record(record):
    canonical, _ = normalize_field_aliases(record)
    return {key: value for key, value in canonical.items() if key in TELEMETRY_FIELDS}


def validate_units(units, uids):
    if not isinstance(units, list):
        raise ValueError("Labels must contain a units array")
    seen_units, seen_flows = set(), set()
    result = []
    for unit in units:
        if not isinstance(unit, dict) or not isinstance(unit.get("unit_id"), str) or not unit["unit_id"]:
            raise ValueError("Each label unit requires a nonempty unit_id")
        uid = unit["unit_id"]
        flows, label, expected = unit.get("flow_ids"), unit.get("label"), unit.get("expected_classes")
        if uid in seen_units or label not in {"attack", "benign", "unknown"}:
            raise ValueError("Duplicate unit_id or invalid label")
        if not isinstance(flows, list) or not flows or any(not isinstance(x, str) or not x for x in flows) or len(set(flows)) != len(flows):
            raise ValueError("Unit flow_ids must be distinct nonempty strings")
        if not isinstance(expected, list) or any(not isinstance(x, str) or x not in CLASSES for x in expected) or len(set(expected)) != len(expected):
            raise ValueError("Unknown or duplicate expected class")
        if (label == "attack") != bool(expected) or ("any_attack" in expected and len(expected) != 1):
            raise ValueError("Only attack units have expected_classes; any_attack cannot be mixed with specific classes")
        if set(flows) & seen_flows or not set(flows) <= uids:
            raise ValueError("Label references overlap or reference missing input UIDs")
        seen_units.add(uid)
        seen_flows.update(flows)
        result.append({"unit_id": uid, "flow_ids": flows, "label": label, "expected_classes": expected})
    # Missing labels are explicit unknowns, never silently benign.
    for uid in sorted(uids - seen_flows):
        identity = f"unlabelled:{uid}"
        while identity in seen_units:
            identity = "unlabelled:" + identity
        seen_units.add(identity)
        result.append({"unit_id": identity, "flow_ids": [uid], "label": "unknown", "expected_classes": []})
    return result


def _number(value):
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("Expected finite nonnegative number")
    return result


def _port(value, protocol):
    if protocol not in {"tcp", "udp"}:
        return 0  # ICMP type/code is not a TCP/UDP service port.
    if not isinstance(value, str):
        raise ValueError("Missing TCP/UDP port")
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def ctu13_records(text, offset_minutes):
    if not isinstance(offset_minutes, int) or not -840 <= offset_minutes <= 840:
        raise ValueError("CTU timestamps require explicit UTC offset minutes")
    reader = csv.DictReader(io.StringIO(text))
    required = {"StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "TotBytes", "SrcBytes", "Label"}
    if not reader.fieldnames or not required <= set(reader.fieldnames):
        raise ValueError("Missing required CTU-13 Argus columns")
    records, units, labels, failures = [], [], Counter(), []
    for line, row in enumerate(reader, 2):
        uid = f"argus-line-{line}"
        label_text = str(row.get("Label", ""))
        labels[label_text] += 1
        # The publisher explicitly warns that To-Botnet is NOT proof of malware.
        parts = label_text.replace("flow=", "").split("-")
        label = "attack" if parts[:2] == ["From", "Botnet"] else "benign" if parts[:2] == ["From", "Normal"] else "unknown"
        units.append({"unit_id": uid, "flow_ids": [uid], "label": label,
                      "expected_classes": ["any_attack"] if label == "attack" else []})
        try:
            timestamp = datetime.strptime(row["StartTime"], "%Y/%m/%d %H:%M:%S.%f").replace(
                tzinfo=timezone(timedelta(minutes=offset_minutes))).timestamp()
            total, sent = _number(row["TotBytes"]), _number(row["SrcBytes"])
            if sent > total or total != int(total) or sent != int(sent):
                raise ValueError("Invalid directional byte counts")
            proto = str(row["Proto"] or "").strip().lower()
            record = {"ts": timestamp, "uid": uid, "id.orig_h": row["SrcAddr"], "id.resp_h": row["DstAddr"],
                      "id.orig_p": _port(row["Sport"], proto), "id.resp_p": _port(row["Dport"], proto),
                      "proto": proto, "duration": _number(row["Dur"]),
                      "orig_bytes": int(sent), "resp_bytes": int(total-sent)}
            # Argus State is not Zeek conn_state. Total packets are not directional
            # packets. Do not fabricate SYN state, DNS queries or TLS fingerprints.
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            record = {"uid": uid}  # normalizer rejects; label remains in denominator
            if len(failures) < 5:
                failures.append({"line": line, "error": str(exc)})
        records.append(record)
    return records, units, {"source_label_counts": dict(labels), "adapter_errors": failures,
        "adapter": "ctu13-argus-v1", "bytes_semantics": "Argus source/total bytes, not Zeek payload bytes",
        "missing_features": ["directional packet counts", "Zeek connection state", "DNS queries", "TLS fingerprints", "packet sequences"],
        "label_scope": "From-Botnet is generic malicious flow, not a beaconing/subtype annotation; To-* and Background remain unknown",
        "direction_note": "Argus source/destination as observed; initiator not guaranteed, especially midstream"}


def prepare_dataset(text, source, *, format, labels=None, offset_minutes=None):
    if format == "ctu13-binetflow":
        try:
            records, units, details = ctu13_records(text, offset_minutes)
        except csv.Error as exc:
            raise ValueError(f"Invalid Argus CSV: {exc}") from exc
    elif format == "zeek-jsonl":
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("Benchmark JSONL records must be objects")
        units, details = labels, {"adapter": "zeek-benchmark-v1"}
        records = [clean_record(record) for record in records]
    else:
        raise ValueError("Unsupported benchmark format")
    if not records:
        raise ValueError("Empty benchmark input")
    uids = [record.get("uid", "") for record in records]
    if any(not isinstance(uid, str) or not uid for uid in uids) or len(set(uids)) != len(uids):
        raise ValueError("Benchmark input requires unique nonempty UIDs")
    units = validate_units(units, set(uids))
    prepared = prepare_replay("\n".join(json.dumps(record) for record in records), source, maximum_records=None)
    fingerprints = set()
    for event in prepared.ordered_events():
        canonical = asdict(event)
        for key in ("raw", "source", "flow_id"):
            canonical.pop(key)
        for key in ("src_ip", "dst_ip"):
            canonical[key] = str(ip_address(canonical[key]))
        canonical["kind"] = type(event).__name__
        # The identity comes from normalized input features, not declared UID,
        # label, field aliases or optional-field spelling/default differences.
        if "packet_observations" in event.raw:
            canonical["packet_observations"] = event.raw["packet_observations"]
        fingerprints.add(sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    return prepared, units, details, fingerprints
