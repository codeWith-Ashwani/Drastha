"""Offline synthetic PCAP -> installed Zeek -> actual upload/analyst API smoke.

No packets are transmitted. Missing Zeek is BLOCKED (exit 2), never a pass.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
from ipaddress import ip_address
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.api_store import IncidentRepository
from aegisflow.analysis_session import UPLOAD_DEMO
from aegisflow.ingestion.zeek_runner import ZeekRunner, WSLZeekRunner
from aegisflow.replay_service import analyse_replay_file
from aegisflow.security import AccessSettings
from check_sustained_ingestion import isolated_api


def checksum(data):
    data += b"\x00" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def scan_pcap():
    """Six synthetic TCP SYNs across ports; valid checksums, no payload."""
    src, dst = ip_address("192.0.2.10").packed, ip_address("198.51.100.20").packed
    capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index in range(6):
        tcp = struct.pack("!HHIIBBHHH", 40000 + index, 1000 + index, 1, 0, 0x50, 2, 65535, 0, 0)
        tcp = tcp[:16] + struct.pack("!H", checksum(src + dst + struct.pack("!BBH", 0, 6, len(tcp)) + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 40, index, 0, 64, 6, 0) + src + dst
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        packet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + tcp
        capture += struct.pack("<IIII", 1788336000, index * 100000, len(packet), len(packet)) + packet
    return capture


SENSOR_BASE_TS = 1_788_336_000
TLS_SOURCE = "192.0.2.30"
TLS_DESTINATION = "198.51.100.30"
TLS_SOURCE_PORT = 43000


def _ipv4_packet(source, destination, protocol, payload, identifier):
    src, dst = ip_address(source).packed, ip_address(destination).packed
    header = struct.pack(
        "!BBHHHBBH", 0x45, 0, 20 + len(payload), identifier, 0, 64, protocol, 0
    ) + src + dst
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def _ethernet(ip_packet):
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip_packet


def _tcp_frame(source, destination, source_port, destination_port, sequence, acknowledgement,
               flags, payload=b"", identifier=1):
    src, dst = ip_address(source).packed, ip_address(destination).packed
    segment = struct.pack(
        "!HHIIBBHHH", source_port, destination_port, sequence, acknowledgement,
        0x50, flags, 65535, 0, 0
    ) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return _ethernet(_ipv4_packet(source, destination, 6, segment, identifier))


def _udp_frame(source, destination, source_port, destination_port, payload, identifier):
    datagram = struct.pack("!HHHH", source_port, destination_port, len(payload) + 8, 0) + payload
    return _ethernet(_ipv4_packet(source, destination, 17, datagram, identifier))


def _dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def _dns_packets():
    name = _dns_name("sensor-check.example")
    question = name + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0x1901, 0x0100, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_address("203.0.113.5").packed
    response = struct.pack("!HHHHHH", 0x1901, 0x8180, 1, 1, 0, 0) + question + answer
    return [
        (SENSOR_BASE_TS + 1.0, _udp_frame("192.0.2.20", "198.51.100.53", 42000, 53, query, 20)),
        (SENSOR_BASE_TS + 1.05, _udp_frame("198.51.100.53", "192.0.2.20", 53, 42000, response, 21)),
    ]


def _tls_record(handshake_type, body):
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _tls_packets():
    host = b"sensor-check.example"
    server_name = len(host).to_bytes(2, "big") + host
    sni = struct.pack("!HHH", 0, len(server_name) + 3, len(server_name) + 1) + b"\x00" + server_name
    groups = struct.pack("!HHHH", 10, 4, 2, 23)
    formats = struct.pack("!HH", 11, 2) + b"\x01\x00"
    extensions = sni + groups + formats
    client_body = (
        b"\x03\x03" + b"C" * 32 + b"\x00" + b"\x00\x02\x13\x01"
        + b"\x01\x00" + len(extensions).to_bytes(2, "big") + extensions
    )
    server_body = b"\x03\x03" + b"S" * 32 + b"\x00\x13\x01\x00\x00\x00"
    client_hello = _tls_record(1, client_body)
    server_hello = _tls_record(2, server_body)
    source, destination = TLS_SOURCE, TLS_DESTINATION
    sport, dport = TLS_SOURCE_PORT, 443
    return [
        (SENSOR_BASE_TS + 2.00, _tcp_frame(source, destination, sport, dport, 1000, 0, 0x02, identifier=30)),
        (SENSOR_BASE_TS + 2.01, _tcp_frame(destination, source, dport, sport, 5000, 1001, 0x12, identifier=31)),
        (SENSOR_BASE_TS + 2.02, _tcp_frame(source, destination, sport, dport, 1001, 5001, 0x10, identifier=32)),
        (SENSOR_BASE_TS + 2.03, _tcp_frame(source, destination, sport, dport, 1001, 5001, 0x18,
                                          client_hello, 33)),
        (SENSOR_BASE_TS + 2.04, _tcp_frame(destination, source, dport, sport, 5001,
                                          1001 + len(client_hello), 0x18, server_hello, 34)),
        (SENSOR_BASE_TS + 2.10, _tcp_frame(source, destination, sport, dport,
                                          1001 + len(client_hello), 5001 + len(server_hello), 0x11,
                                          identifier=35)),
        (SENSOR_BASE_TS + 2.11, _tcp_frame(destination, source, dport, sport,
                                          5001 + len(server_hello), 1002 + len(client_hello), 0x11,
                                          identifier=36)),
    ]


def sensor_pcap():
    """Offline deterministic SYN, DNS and TLS traffic; never opens a network interface."""
    frames = []
    scan = scan_pcap()
    offset = 24
    while offset < len(scan):
        seconds, micros, captured, _ = struct.unpack_from("<IIII", scan, offset)
        packet = scan[offset + 16:offset + 16 + captured]
        frames.append((seconds + micros / 1_000_000, packet))
        offset += 16 + captured
    frames.extend(_dns_packets())
    frames.extend(_tls_packets())
    capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for timestamp, packet in sorted(frames):
        seconds = int(timestamp)
        micros = round((timestamp - seconds) * 1_000_000)
        capture += struct.pack("<IIII", seconds, micros, len(packet), len(packet)) + packet
    return capture


def _json_log_inventory(directory):
    inventory = {}
    for name in ("conn.log", "dns.log", "ssl.log", "quic.log"):
        path = directory / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        records = sum(1 for line in raw.splitlines() if line.strip() and not line.lstrip().startswith(b"#"))
        inventory[name] = {"records": records, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    return inventory


@contextmanager
def deny_detector_network_connections():
    """Fail if Python analysis attempts an outbound connection to an observed endpoint."""
    attempted = []
    real_socket = socket.socket

    class PassiveSocket(real_socket):
        def connect(self, address):
            attempted.append(repr(address))
            raise RuntimeError("Passive analysis attempted a network connection")

        def connect_ex(self, address):
            attempted.append(repr(address))
            raise RuntimeError("Passive analysis attempted a network connection")

    def denied_create_connection(address, *args, **kwargs):
        attempted.append(repr(address))
        raise RuntimeError("Passive analysis attempted a network connection")

    with patch("socket.socket", PassiveSocket), patch("socket.create_connection", denied_create_connection):
        yield attempted


def probe(mode="auto", binary=None, distribution=None):
    attempts = []
    candidates = []
    if mode in {"auto", "native"}:
        executable = binary or "zeek"
        resolved = ZeekRunner(executable).resolved_executable()
        if resolved:
            candidates.append((ZeekRunner(resolved), [resolved, "--version"]))
        else:
            attempts.append({"mode": "native", "error": "Zeek executable not found"})
    if mode in {"auto", "wsl"}:
        wsl = shutil.which("wsl.exe")
        if wsl:
            runner = WSLZeekRunner(binary or "/opt/zeek/bin/zeek", distribution, wsl)
            candidates.append((runner, runner._base_command() + ["--", runner.executable, "--version"]))
        else:
            attempts.append({"mode": "wsl", "error": "wsl.exe not found"})
    for runner, command in candidates:
        try:
            completed = subprocess.run(command, capture_output=True, timeout=15, check=False)
            # WSL errors can be UTF-16LE while successful Zeek output is UTF-8.
            raw = completed.stdout + completed.stderr
            message = raw.decode("utf-16-le" if b"\x00" in raw else "utf-8", errors="replace").strip()
            if completed.returncode == 0 and "zeek" in message.lower():
                return runner, {"status": "available", "version": message, "command": command, "attempts": attempts}
            attempts.append({"command": command, "returncode": completed.returncode, "error": message[:2000]})
        except (OSError, subprocess.TimeoutExpired) as exc:
            attempts.append({"command": command, "error": str(exc)})
    return None, {"status": "blocked", "attempts": attempts, "reason": "No runnable local Zeek installation"}


def check(mode="auto", binary=None, distribution=None):
    runner, availability = probe(mode, binary, distribution)
    result = {"experiment": "offline-real-zeek-upload-v2", "sensor": availability,
              "status": "blocked", "passed": False,
              "limitations": ["Synthetic offline SYN/DNS/TLS PCAP, not a live mirror or throughput test",
                              "Validates Zeek connection, DNS and TLS metadata; QUIC sensor interoperability remains open",
                              "A single TLS session validates measured feature availability, not anomaly classification or baseline calibration",
                              "Actual in-process ASGI upload/readback, not browser or TLS transport validation"]}
    if runner is None:
        return result
    from fastapi.testclient import TestClient
    with tempfile.TemporaryDirectory(prefix="drastha-sensor-") as folder:
        directory = Path(folder)
        capture = sensor_pcap()
        path = directory / "sensor-mixed.pcap"
        path.write_bytes(capture)
        try:
            converted = runner.process_pcap(path, directory / "zeek")
            before_logs = _json_log_inventory(converted.output_directory)
            repository = IncidentRepository(directory / "analyst.db")
            with deny_detector_network_connections() as attempted_connections:
                report = analyse_replay_file(
                    converted.output_directory,
                    repository,
                    root=ROOT,
                    profile=UPLOAD_DEMO,
                    packet_capture=path,
                )
            with isolated_api(directory) as create_app:
                app = create_app(repository, access=AccessSettings())
            with TestClient(app) as client:
                readback = client.get("/api/analysis-runs/" + report["run_id"])
                readback.raise_for_status()
            after_logs = _json_log_inventory(converted.output_directory)
            packet_schema = report["input_schema"].get("packet_capture", {})
            feature_counts = report["feature_coverage"]["counts"]
            gates = {"connections_present": report["telemetry"]["connection_records"] >= 8,
                     "dns_metadata_present": report["telemetry"]["dns_records"] >= 1,
                     "tls_metadata_present": report["telemetry"]["encrypted_session_records"] >= 1,
                     "none_rejected_healthy": report["quality"]["records_rejected"] == 0
                                                and report["quality"]["status"] == "healthy",
                     "recon_detected": any(a["threat_type"] == "reconnaissance" for a in report["alerts"]),
                     "api_readback": readback.json() == json.loads(json.dumps(report)),
                     "pcap_unchanged": path.read_bytes() == capture,
                     "zeek_output_unchanged": before_logs == after_logs,
                     "zeek_dns_log_observed": before_logs.get("dns.log", {}).get("records", 0) >= 1,
                     "zeek_tls_log_observed": before_logs.get("ssl.log", {}).get("records", 0) >= 1,
                     "capture_packets_joined": packet_schema.get("counters", {}).get("matched_packets", 0) >= 4,
                     "capture_fingerprint_observed": feature_counts.get("fingerprint_missing", 0) == 0,
                     "capture_sequence_observed": feature_counts.get("sequence_unavailable", 0) == 0,
                     "payload_not_decrypted": packet_schema.get("payload_decrypted") is False,
                     "application_payload_not_retained": packet_schema.get("application_payload_retained") is False,
                     "no_detector_network_connections": attempted_connections == []}
            result.update(status="passed" if all(gates.values()) else "failed", passed=all(gates.values()),
                          gates=gates, quality=report["quality"], findings=len(report["alerts"]),
                          incidents=len(report["incidents"]), telemetry=report["telemetry"],
                          feature_coverage=report["feature_coverage"],
                          input_schema=report["input_schema"], zeek_logs=before_logs,
                          detector_network_attempts=attempted_connections,
                          pcap_sha256=sha256(capture).hexdigest(),
                          zeek_command=list(converted.command))
        except Exception as exc:
            result.update(status="failed", error=f"{type(exc).__name__}: {exc}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("auto", "native", "wsl"), default="auto")
    parser.add_argument("--binary")
    parser.add_argument("--distribution")
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    if args.report_output and args.report_output.exists():
        parser.error("Report is create-only; choose a new filename")
    report = check(args.mode, args.binary, args.distribution)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        with args.report_output.open("x", encoding="utf-8") as output:
            output.write(rendered + "\n")
    print(rendered)
    return 0 if report["passed"] else 2 if report["status"] == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
