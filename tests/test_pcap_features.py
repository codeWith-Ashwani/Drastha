import io
import json
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.api_store import IncidentRepository
from aegisflow.cli import main
from aegisflow.ingestion.capture_join import attach_capture
from aegisflow.ingestion.passive_replay import prepare_replay
from aegisflow.ingestion.pcap_metadata import client_hello_ja3, extract_capture, packet_headers
from aegisflow.ingestion.zeek_jsonl import normalize_conn_record
from aegisflow.replay_service import analyse_replay_file


def hello(*, rare=False, grease=False):
    def vector(value, width=2):
        return len(value).to_bytes(width, "big") + value
    ciphers = struct.pack("!H", 0x1302 if rare else 0x1301)
    groups = struct.pack("!HH", 23, 24)
    if grease:
        ciphers = struct.pack("!H", 0x0a0a) + ciphers
        groups = struct.pack("!H", 0x1a1a) + groups
    ext = struct.pack("!HH", 10, len(groups)+2) + vector(groups) + struct.pack("!HH", 11, 2) + b"\x01\x00"
    if grease:
        ext = struct.pack("!HH", 0x2a2a, 0) + ext
    body = b"\x03\x03" + b"\x00"*32 + b"\x00" + vector(ciphers) + b"\x01\x00" + vector(ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + vector(handshake)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data)//2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def frame(source, destination, sport, dport, payload, *, vlan=False, ipv6=False):
    src, dst = ip_address(source).packed, ip_address(destination).packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0) + payload
    pseudo = (src + dst + struct.pack("!I3xB", len(tcp), 6) if ipv6 else
              src + dst + struct.pack("!BBH", 0, 6, len(tcp)))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst
    else:
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20+len(tcp), 1, 0, 64, 6, 0) + src + dst
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ether_type = 0x86dd if ipv6 else 0x0800
    ethernet = b"\x00"*12 + (struct.pack("!HHH", 0x8100, 7, ether_type) if vlan else struct.pack("!H", ether_type))
    return ethernet + ip + tcp


def capture_bytes(packets, *, endian="<", nano=False):
    data = struct.pack(endian+"IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for timestamp, packet in packets:
        seconds = int(timestamp)
        fraction = round((timestamp-seconds)*(1e9 if nano else 1e6))
        data += struct.pack(endian+"IIII", seconds, fraction, len(packet), len(packet)) + packet
    return data


def controlled_fixture(count=404):
    records, packets = [], []
    for index in range(count):
        rare = index >= 400
        ts = 1000 + index*2
        source = "10.0.9.9" if rare else f"10.0.{index//250}.{index%250+1}"
        record = {"ts": ts, "uid": f"P{index}", "id.orig_h": source, "id.resp_h": "198.51.100.8",
                  "id.orig_p": 50000+index, "id.resp_p": 443, "proto": "tcp", "duration": 1,
                  "orig_bytes": 200, "resp_bytes": 200, "conn_state": "SF"}
        records.append(record)
        gap = .1 if rare else .001
        for position in range(4):
            src, dst, sport, dport = source, record["id.resp_h"], record["id.orig_p"], 443
            if position % 2:
                src, dst, sport, dport = dst, src, dport, sport
            payload = hello(rare=rare) if position == 0 else b"\x00"*((1400 if rare else 100)-40)
            packets.append((ts+position*gap, frame(src, dst, sport, dport, payload)))
    return records, packets


class PcapFeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write_capture(self, packets, **kwargs):
        path = self.folder / "traffic.pcap"
        path.write_bytes(capture_bytes(packets, **kwargs))
        return path

    def test_ja3_vectors_grease_and_truncation(self):
        signature, fingerprint = client_hello_ja3(hello())
        self.assertEqual(signature, "771,4865,10-11,23-24,0")
        self.assertEqual(client_hello_ja3(hello(grease=True)), (signature, fingerprint))
        self.assertNotEqual(client_hello_ja3(hello(rare=True))[1], fingerprint)
        self.assertIsNone(client_hello_ja3(hello()[:-1]))
        self.assertIsNone(client_hello_ja3(b"\x17" + hello()[1:]))

    def test_actual_capture_through_shared_cli_with_no_supplied_scores(self):
        records, packets = controlled_fixture()
        path = self.write_capture(packets)
        before = sha256(path.read_bytes()).hexdigest()
        logs = self.folder / "conn.jsonl"
        logs.write_text("\n".join(map(json.dumps, records)), encoding="utf-8")
        repository = IncidentRepository(self.folder / "run.db")
        report = analyse_replay_file(logs, repository, root=ROOT, packet_capture=path)
        self.assertEqual(sha256(path.read_bytes()).hexdigest(), before)
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual(report["quality"]["records_accepted"], 404)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["subtype"], "encrypted_session_metadata_anomaly")
        evidence = {item["name"]: item["observed"] for item in report["alerts"][0]["evidence"]}
        self.assertEqual(evidence["feature_origin"], "derived")
        self.assertEqual(evidence["capture_sha256"], before)
        self.assertEqual(report["input_schema"]["packet_capture"]["counters"]["matched_packets"], 1616)
        self.assertEqual(report["feature_coverage"]["counts"]["derived"], 304)
        output = self.folder / "report.json"
        with redirect_stdout(io.StringIO()):
            code = main(["analyse", "--input", str(logs), "--packet-capture", str(path), "--root", str(ROOT),
                         "--report-output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text())["alerts"], json.loads(json.dumps(report["alerts"])))

    def test_join_by_uid_endpoints_and_time_and_observation_availability(self):
        records, packets = controlled_fixture(1)
        path = self.write_capture(packets)
        ssl = {"ts": 1000, "uid": "P0", "transport": "tls", "id.orig_h": records[0]["id.orig_h"],
               "id.resp_h": records[0]["id.resp_h"], "ja4": "sensor-ja4"}
        prepared = prepare_replay("\n".join(map(json.dumps, records+[ssl])))
        original = json.dumps(prepared.accepted_records, sort_keys=True)
        attach_capture(prepared, path)
        metadata = prepared.encrypted_events[0]
        self.assertEqual(len(prepared.encrypted_events), 1)
        self.assertEqual(metadata.client_fingerprint, "sensor-ja4")
        self.assertEqual(metadata.timestamp, 1000.003)
        self.assertEqual(metadata.raw["source_metadata_ts"], 1000)
        self.assertEqual([p["direction"] for p in metadata.raw["packet_observations"]], ["orig", "resp", "orig", "resp"])
        self.assertEqual(json.dumps(prepared.accepted_records, sort_keys=True), original)
        self.assertNotIn("payload", json.dumps(metadata.raw))
        ssl["ts"] = 1020
        unmatched = attach_capture(prepare_replay("\n".join(map(json.dumps, records+[ssl]))), path)
        self.assertEqual(unmatched.encrypted_events[0].raw["packet_observations"], [])
        self.assertEqual(unmatched.input_schema["packet_capture"]["join"]["unmatched_or_ambiguous_metadata"], 1)

    def test_packet_direction_vlan_ipv6_and_pcap_endianness(self):
        records, packets = controlled_fixture(1)
        event = normalize_conn_record(records[0])
        for endian in ("<", ">"):
            for nano in (False, True):
                result = extract_capture(self.write_capture(packets, endian=endian, nano=nano), [event])
                self.assertEqual(result.report["counters"]["matched_packets"], 4)
        for ipv6 in (False, True):
            src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("10.0.0.1", "198.51.100.8")
            parsed, reason = packet_headers(frame(src, dst, 50000, 443, hello(), vlan=True, ipv6=ipv6))
            self.assertIsNone(reason)
            self.assertEqual(parsed[0], (src, 50000, dst, 443, "tcp"))
            self.assertIsNotNone(parsed[2])

    def test_ambiguous_or_outside_flow_packets_are_not_guessed(self):
        records, packets = controlled_fixture(1)
        event = normalize_conn_record(records[0])
        capture = extract_capture(self.write_capture(packets), [event, replace(event, flow_id="another")])
        self.assertEqual(capture.report["counters"]["ambiguous_packets"], 4)
        self.assertEqual(capture.sequences, {})
        late = extract_capture(self.write_capture(packets), [replace(event, timestamp=1002)])
        self.assertEqual(late.report["counters"]["unmatched_packets"], 4)

    def test_capture_timestamp_regression_keeps_quality_degraded(self):
        records, packets = controlled_fixture(1)
        packets[1], packets[2] = packets[2], packets[1]
        prepared = attach_capture(prepare_replay(json.dumps(records[0])), self.write_capture(packets))
        self.assertEqual(prepared.quality.status, "degraded")
        self.assertEqual(prepared.input_schema["packet_capture"]["counters"]["out_of_order_packets"], 1)

    def test_late_clienthello_never_available_before_its_capture_time(self):
        records, packets = controlled_fixture(1)
        packet = packets[0][1]
        # First 128 packets retained; ClientHello first arrives after that prefix.
        empty = frame(records[0]["id.orig_h"], records[0]["id.resp_h"], records[0]["id.orig_p"], 443, b"")
        packets = [(1000+i*.001, empty) for i in range(128)] + [(1000.5, packet)]
        prepared = attach_capture(prepare_replay(json.dumps(records[0])), self.write_capture(packets))
        self.assertEqual(prepared.encrypted_events[0].timestamp, 1000.5)
        self.assertEqual(len(prepared.encrypted_events[0].raw["packet_observations"]), 128)
        self.assertEqual(prepared.input_schema["packet_capture"]["counters"]["sequence_tail_not_retained"], 1)

    def test_conflicting_hellos_do_not_produce_guessed_fingerprint(self):
        records, packets = controlled_fixture(1)
        event = normalize_conn_record(records[0])
        packets.append((1000.5, frame(event.src_ip, event.dst_ip, event.src_port, event.dst_port, hello(rare=True))))
        capture = extract_capture(self.write_capture(packets), [event])
        self.assertIsNone(capture.fingerprints[(event.flow_id, event.src_ip, event.dst_ip)])
        self.assertEqual(capture.report["counters"]["conflicting_client_hellos"], 1)

    def test_unsupported_and_corrupted_capture_fail_explicitly(self):
        path = self.folder / "invalid.pcap"
        for data in (b"\x0a\x0d\x0d\x0a", capture_bytes([])+b"short"):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                extract_capture(path, [])
        records, packets = controlled_fixture(1)
        path = self.write_capture(packets)
        with self.assertRaises(ValueError):
            extract_capture(path, [normalize_conn_record(records[0])], maximum_packets=1)

    def test_fragmented_ip_is_not_used_as_complete_packet_sequence(self):
        _, packets = controlled_fixture(1)
        packet = packets[0][1]
        fragmented = packet[:20] + b"\x20\x00" + packet[22:]
        self.assertEqual(packet_headers(fragmented)[1], "fragmented_ip")


if __name__ == "__main__":
    unittest.main()
