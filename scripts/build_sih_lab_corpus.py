"""Build Drastha's deterministic, offline SIH-26145 lab corpus.

The generator creates metadata-only semantic equivalents of the traffic tools
named in the problem statement.  It never opens a socket, runs an attack tool,
or embeds ground truth in detector input.  Labels live in checksum-pinned
sidecars and every capture is processed with a fresh analysis session.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path


VERSION = "sih26145-lab-v1"
BASE_TS = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc).timestamp()
REQUIRED = ("ts", "uid", "id.orig_h", "id.resp_h", "proto")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _jsonl_bytes(records: list[dict]) -> bytes:
    return ("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in records)).encode()


def _conn(uid: str, ts: float, src: str, dst: str, dport: int, *, proto: str = "tcp",
          sport: int = 40000, duration: float = 0.2, sent: int = 500, received: int = 700,
          sent_packets: int = 5, received_packets: int = 6, state: str = "SF",
          service: str = "") -> dict:
    return {"ts": round(ts, 6), "uid": uid, "id.orig_h": src, "id.resp_h": dst,
            "id.orig_p": sport, "id.resp_p": dport, "proto": proto,
            "duration": duration, "orig_bytes": sent, "resp_bytes": received,
            "orig_pkts": sent_packets, "resp_pkts": received_packets,
            "conn_state": state, "service": service}


def _dns(uid: str, ts: float, src: str, query: str, qtype: str = "A") -> dict:
    return {"ts": round(ts, 6), "uid": uid, "id.orig_h": src, "id.resp_h": "10.0.0.53",
            "id.orig_p": 53000, "id.resp_p": 53, "proto": "udp", "query": query,
            "qtype_name": qtype, "rcode_name": "NOERROR", "answers": ["203.0.113.9"],
            "rejected": False}


def _packets(ts: float, sizes: list[int], gap: float) -> list[dict]:
    start = ts - gap * (len(sizes) - 1) - 0.001
    return [{"ts": round(start + index * gap, 6), "ip_bytes": size,
             "direction": "orig" if index % 2 == 0 else "resp"}
            for index, size in enumerate(sizes)]


def _tls(uid: str, ts: float, src: str, dst: str, fingerprint: str,
         sizes: list[int], gap: float) -> dict:
    row = _conn(uid, ts, src, dst, 443, sport=45000, sent=900, received=1400,
                sent_packets=4, received_packets=4, service="ssl")
    row.update({"ja4": fingerprint, "server_name": "telemetry.example",
                "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                "next_protocol": "h2", "established": True, "resumed": False,
                "sensor_id": "sih-lab-sensor-1", "packet_observations": _packets(ts, sizes, gap)})
    return row


def _unit(unit_id: str, records: list[dict], label: str, expected: list[str]) -> dict:
    return {"unit_id": unit_id, "flow_ids": [row["uid"] for row in records],
            "label": label, "expected_classes": expected}


def scenarios() -> list[dict]:
    result = []

    def add(identifier: str, guidance: str, records: list[dict], units: list[dict],
            purpose: str, coverage: str = "covered") -> None:
        result.append({"id": identifier, "guidance": guidance, "records": records,
                       "units": units, "purpose": purpose, "coverage": coverage})

    base = BASE_TS
    rows = [_conn(f"LOAD{i:03d}", base + i * 0.7, "10.10.1.10", f"10.10.2.{10+i%20}",
                  5201 if i % 2 == 0 else 443, proto="tcp" if i % 3 else "udp",
                  sport=41000+i, duration=0.4+i%7/10, sent=20000+i*137,
                  received=18000+i*113, sent_packets=20+i%5, received_packets=18+i%5,
                  service="iperf3" if i % 2 == 0 else "https") for i in range(60)]
    add("benign-load-control", "iperf3 / Ostinato / TRex benign load", rows,
        [_unit("benign-load", rows, "benign", [])], "Varied, completed and balanced baseline traffic.")

    base += 600
    rows = [_conn(f"HEALTH{i:03d}", base+i*5, "10.10.3.10", "10.10.3.20", 443,
                  sport=42000+i, sent=160+i%3*17, received=210+i%4*13, service="https") for i in range(8)]
    add("benign-health-control", "legitimate periodic monitoring control", rows,
        [_unit("benign-health", rows, "benign", [])], "Known health-check pattern for contextual false-positive testing.")

    base += 600
    rows = [_conn(f"BACKUP{i:03d}", base+i*12, "10.10.4.10", "198.51.100.50", 443,
                  sport=43000+i, duration=9, sent=12_000_000+i*1000, received=250_000,
                  sent_packets=9000, received_packets=500, service="ssl") for i in range(3)]
    add("benign-backup-control", "approved backup / update control", rows,
        [_unit("benign-backup", rows, "benign", [])], "Approved high-ratio transfer for policy correlation testing.")

    base += 600
    rows = [_conn(f"AUTHSCAN{i:03d}", base+i*0.2, "10.10.5.10", "10.10.5.20", 1000+i,
                  sport=44000+i, sent=60, received=0, sent_packets=1, received_packets=0,
                  state="S0") for i in range(22)]
    add("authorized-scanner-control", "authorized scanner control", rows,
        [_unit("authorized-scanner", rows, "benign", [])], "Authorized scan-shaped activity for policy correlation testing.")

    base += 600
    rows = [_conn(f"SYN{i:03d}", base+i*0.03, "10.20.1.10", "10.20.1.99", 443,
                  sport=20000+i, sent=0, received=0, sent_packets=1, received_packets=0,
                  state="S0") for i in range(110)]
    add("syn-flood", "hping3 SYN mode offline semantic equivalent", rows,
        [_unit("attack-syn-flood", rows, "attack", ["volumetric_ddos_syn_flood"])],
        "Concentrated incomplete SYN attempts to one service.")

    base += 600
    rows = [_conn(f"UDPAMP{i:03d}", base+i*0.5, "10.20.2.99", f"198.51.100.{10+i}", 53,
                  proto="udp", sport=53000+i, sent=60, received=6000, sent_packets=1,
                  received_packets=8, state="SF", service="dns") for i in range(5)]
    add("udp-reflection-amplification", "hping3 UDP/reflection offline semantic equivalent", rows,
        [_unit("attack-udp-amplification", rows, "attack", ["udp_reflection_amplification"])],
        "Small requests with much larger responses from DNS service endpoints.")

    base += 600
    rows = [_conn(f"SLOWHTTP{i:03d}", base+i*0.4, "10.20.3.10", "10.20.3.99", 80,
                  sport=25000+i, duration=240, sent=120, received=30, sent_packets=3,
                  received_packets=1, state="S1", service="http") for i in range(24)]
    add("slow-http-exhaustion", "Slowloris offline semantic equivalent", rows,
        [_unit("attack-slow-http", rows, "attack", ["any_attack"])],
        "Long-lived partial HTTP sessions; retained as an explicit coverage probe.", "known-gap")

    base += 600
    rows = [_conn(f"C2{i:03d}", base+i*7, "10.20.4.10", "203.0.113.44", 8443,
                  sport=26000+i, sent=180, received=220, sent_packets=3, received_packets=3,
                  service="ssl") for i in range(8)]
    add("c2-beacon", "sandboxed C2 emulator offline semantic equivalent", rows,
        [_unit("attack-c2", rows, "attack", ["botnet_c2_beaconing"])],
        "Regular low-volume completed callbacks to one endpoint.")

    base += 600
    names = ["q7x9z2k4m8n1", "v3b8q0x6z9k2", "m9x2q7v4z8b1"]
    rows = [_dns(f"DGA{i:03d}", base+i, "10.20.5.10", name+".invalid") for i, name in enumerate(names)]
    add("dga-domains", "DGA algorithms / DGArchive-style offline semantic equivalent", rows,
        [_unit("attack-dga", rows, "attack", ["dga_domain"])],
        "Multiple independent digit-heavy, high-entropy domain labels.")

    base += 600
    rows = [_dns(f"DNSTUN{i:03d}", base+i*1.5, "10.20.6.10",
                 f"{i:02x}9af3d7c1b5e8a2f6c0d4e7b1{i:02x}.tunnel.invalid", "TXT") for i in range(20)]
    add("dns-tunnel", "dnscat2 / iodine offline semantic equivalent", rows,
        [_unit("attack-dns-tunnel", rows, "attack", ["dns_tunnelling"])],
        "Repeated long, unique, encoded-looking TXT subdomains.")

    base += 600
    normal = [_tls(f"TLSBASE{i:03d}", base+i*0.4, f"10.30.1.{10+i%20}", "203.0.113.80",
                   f"t13d1516h2_{i%10:02d}", [120, 1500, 90, 1200, 80, 700, 70, 500], 0.008)
              for i in range(100)]
    attack = [_tls(f"TLSANOM{i:03d}", base+41+i*3, "10.30.2.10", "203.0.113.88",
                   "t13d9999h2_rare", [1400, 80, 1450, 70, 1300, 60, 1250, 55], 0.080)
              for i in range(4)]
    rows = normal + attack
    add("encrypted-session-anomaly", "TLS/QUIC metadata-only malware-anomaly scenario", rows,
        [_unit("benign-tls-baseline", normal, "benign", []),
         _unit("attack-encrypted-anomaly", attack, "attack", ["encrypted_session_malware"])],
        "Causal prevalence and packet-size/timing features; no decryption.")

    base += 600
    rows = [_conn(f"RECON{i:03d}", base+i*0.25, "10.20.7.10", "10.20.7.99", 2000+i,
                  sport=27000+i, sent=60, received=0, sent_packets=1, received_packets=0,
                  state="S0") for i in range(22)]
    add("reconnaissance", "network scanner offline semantic equivalent", rows,
        [_unit("attack-recon", rows, "attack", ["reconnaissance_port_scan"])],
        "Single-source destination-port fan-out.")

    base += 600
    rows = [_conn(f"EXFIL{i:03d}", base+i*20, "10.20.8.10", "203.0.113.99", 443,
                  sport=28000+i, duration=15, sent=12_000_000+i*100_000, received=100_000,
                  sent_packets=8500, received_packets=300, service="ssl") for i in range(3)]
    add("data-exfiltration", "outbound bulk-transfer offline semantic equivalent", rows,
        [_unit("attack-exfil", rows, "attack", ["data_exfiltration"])],
        "Unapproved extreme outbound/inbound byte asymmetry.")
    return result


def build(repo_root: Path) -> dict[Path, bytes]:
    data_root = repo_root / "data"
    relative_root = Path("lab") / VERSION
    artifacts = []
    files: dict[Path, bytes] = {}
    for scenario in scenarios():
        records = scenario["records"]
        telemetry = _jsonl_bytes(records)
        labels = _json_bytes({"schema_version": "drastha-label-units-v1", "units": scenario["units"]})
        telemetry_path = relative_root / f"{scenario['id']}.jsonl"
        labels_path = relative_root / f"{scenario['id']}.labels.json"
        files[data_root / telemetry_path] = telemetry
        files[data_root / labels_path] = labels
        artifacts.append({"id": scenario["id"], "capture_id": f"capture:{VERSION}:{scenario['id']}",
                          "group_ids": [f"scenario:{scenario['id']}", f"corpus:{VERSION}"],
                          "split": "test", "format": "zeek-jsonl", "path": telemetry_path.as_posix(),
                          "sha256": sha256(telemetry).hexdigest(), "expected_records": len(records),
                          "labels": {"path": labels_path.as_posix(), "sha256": sha256(labels).hexdigest()},
                          "origin": {"kind": "synthetic", "method": "deterministic offline metadata semantic equivalent"},
                          "scenario": {"problem_statement_guidance": scenario["guidance"],
                                       "purpose": scenario["purpose"], "coverage_status": scenario["coverage"]}})
    sensor_path = repo_root / "output" / "sprint19_sensor_integration.json"
    manifest = {"schema_version": "drastha-corpus-v1", "corpus_id": VERSION,
                "description": "Safe offline SIH-26145 lab corpus with independent ground truth.",
                "generated_at": "2026-09-02T08:00:00Z", "internal_cidrs": ["10.0.0.0/8"],
                "safety": {"active_network_transmission": False, "attack_tools_executed": False,
                           "payload_decryption": False, "ground_truth_in_telemetry": False},
                "provenance_tier": "offline_semantic_equivalent",
                "sensor_anchor": {"path": "output/sprint19_sensor_integration.json",
                                  "sha256": sha256(sensor_path.read_bytes()).hexdigest(),
                                  "claim": "Separate real Zeek 8.0.10 conn/DNS/TLS interoperability proof; not the source of every scenario."},
                "artifacts": artifacts}
    files[data_root / "manifests" / f"{VERSION}.json"] = _json_bytes(manifest)
    return files


def validate(files: dict[Path, bytes]) -> None:
    seen = set()
    for path, payload in files.items():
        if path.suffix != ".jsonl":
            continue
        rows = [json.loads(line) for line in payload.decode().splitlines()]
        timestamps = [float(row["ts"]) for row in rows]
        assert timestamps == sorted(timestamps), f"timestamp regression: {path}"
        for row in rows:
            assert all(field in row for field in REQUIRED), f"missing required field: {path}"
            assert row["uid"] not in seen, f"duplicate UID: {row['uid']}"
            seen.add(row["uid"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = build(args.repo_root.resolve())
    validate(files)
    if args.check:
        changed = [str(path) for path, payload in files.items() if not path.is_file() or path.read_bytes() != payload]
        if changed:
            raise SystemExit("Corpus differs from deterministic generator:\n" + "\n".join(changed))
        print(f"{VERSION}: {len(scenarios())} scenarios reproducible")
        return 0
    existing = [str(path) for path in files if path.exists()]
    if existing:
        raise SystemExit("Refusing to overwrite immutable corpus files:\n" + "\n".join(existing))
    for path, payload in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    print(f"Created {len(scenarios())} scenarios and {len(files)} immutable files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
