"""Offline synthetic PCAP -> installed Zeek -> actual upload/analyst API smoke.

No packets are transmitted. Missing Zeek is BLOCKED (exit 2), never a pass.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from ipaddress import ip_address
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.api_store import IncidentRepository
from aegisflow.ingestion.zeek_runner import ZeekRunner, WSLZeekRunner
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
    result = {"experiment": "offline-real-zeek-upload-v1", "sensor": availability,
              "status": "blocked", "passed": False,
              "limitations": ["Synthetic six-packet offline PCAP, not a live mirror or throughput test",
                              "Tests installed Zeek conn.log and recon only; DNS/TLS/QUIC sensor interoperability remains open",
                              "Actual in-process ASGI upload/readback, not browser or TLS transport validation"]}
    if runner is None:
        return result
    from fastapi.testclient import TestClient
    with tempfile.TemporaryDirectory(prefix="drastha-sensor-") as folder:
        directory = Path(folder)
        capture = scan_pcap()
        path = directory / "scan.pcap"
        path.write_bytes(capture)
        try:
            converted = runner.process_pcap(path, directory / "zeek")
            raw = converted.conn_log.read_bytes()
            with isolated_api(directory) as create_app:
                app = create_app(IncidentRepository(directory / "analyst.db"), access=AccessSettings())
            with TestClient(app) as client:
                response = client.post("/api/replays/analyse", json={"filename": "conn.jsonl", "content": raw.decode()})
                response.raise_for_status()
                report = response.json()
                readback = client.get("/api/analysis-runs/" + report["run_id"])
                readback.raise_for_status()
            gates = {"six_accepted": report["quality"]["records_accepted"] == 6,
                     "none_rejected": report["quality"]["records_rejected"] == 0,
                     "recon_detected": any(a["threat_type"] == "reconnaissance" for a in report["alerts"]),
                     "api_readback": readback.json() == report,
                     "pcap_unchanged": path.read_bytes() == capture,
                     "zeek_output_unchanged": converted.conn_log.read_bytes() == raw}
            result.update(status="passed" if all(gates.values()) else "failed", passed=all(gates.values()),
                          gates=gates, quality=report["quality"], findings=len(report["alerts"]),
                          pcap_sha256=sha256(capture).hexdigest(), conn_sha256=sha256(raw).hexdigest())
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
