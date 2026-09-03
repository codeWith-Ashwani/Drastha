"""Read-only classic-PCAP metadata extraction. No sockets or payload decryption.

Supported: Ethernet (including VLAN), IPv4/IPv6 without fragmentation/extension
chains, TCP/UDP. JA3 is extracted only from a complete cleartext ClientHello in
one TCP segment. Unsupported packets and incomplete hellos are counted, not
invented. Application payload is never returned or persisted.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import md5, sha256
from ipaddress import ip_address
import math
from pathlib import Path
import struct


VERSION = "pcap-header-ja3-v1"


def client_hello_ja3(payload: bytes):
    """Return (JA3 string, digest) for complete TLS record/ClientHello, else None."""
    try:
        if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
            return None
        length = int.from_bytes(payload[3:5], "big")
        if length > 18432 or len(payload) < length + 5:
            return None
        hello_length = int.from_bytes(payload[6:9], "big")
        if hello_length + 4 > length:
            return None
        data = payload[9:9 + hello_length]
        pos = 0

        def take(count):
            nonlocal pos
            if pos + count > len(data):
                raise ValueError("incomplete ClientHello")
            value = data[pos:pos + count]
            pos += count
            return value

        def vector(width):
            return take(int.from_bytes(take(width), "big"))

        def words(value):
            if len(value) % 2:
                raise ValueError("odd TLS vector")
            return [int.from_bytes(value[i:i + 2], "big") for i in range(0, len(value), 2)]

        def grease(value):
            return value & 0x0F0F == 0x0A0A and value >> 8 == value & 255

        version = int.from_bytes(take(2), "big")
        take(32)
        vector(1)  # session ID
        ciphers = [x for x in words(vector(2)) if not grease(x)]
        vector(1)  # compression methods
        extensions, groups, formats = [], [], []
        if pos < len(data):
            ext_data = vector(2)
            index = 0
            while index < len(ext_data):
                if index + 4 > len(ext_data):
                    raise ValueError("short extension")
                kind, size = struct.unpack_from("!HH", ext_data, index)
                index += 4
                value = ext_data[index:index + size]
                if len(value) != size:
                    raise ValueError("short extension value")
                index += size
                if not grease(kind):
                    extensions.append(kind)
                if kind == 10:
                    if len(value) < 2 or int.from_bytes(value[:2], "big") != len(value) - 2:
                        raise ValueError("invalid groups")
                    groups = [x for x in words(value[2:]) if not grease(x)]
                if kind == 11:
                    if not value or value[0] != len(value) - 1:
                        raise ValueError("invalid point formats")
                    formats = list(value[1:])
        if pos != len(data):
            raise ValueError("trailing hello data")
        signature = ",".join((str(version), *("-".join(map(str, x)) for x in
                                               (ciphers, extensions, groups, formats))))
        # JA3 specifies MD5; this is an identifier, not a security integrity hash.
        return signature, md5(signature.encode(), usedforsecurity=False).hexdigest()
    except (ValueError, IndexError, struct.error):
        return None


def packet_headers(frame):
    if len(frame) < 14:
        return None, "short_ethernet"
    protocol = int.from_bytes(frame[12:14], "big")
    offset = 14
    while protocol in {0x8100, 0x88A8}:
        if offset + 4 > len(frame):
            return None, "short_vlan"
        protocol = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    ip = frame[offset:]
    if protocol == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None, "short_ipv4"
        ihl = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        if ihl < 20 or len(ip) < ihl or total < ihl:
            return None, "invalid_ipv4"
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            return None, "fragmented_ip"
        source, destination = str(ip_address(ip[12:16])), str(ip_address(ip[16:20]))
        transport, body = ip[9], ip[ihl:total]
    elif protocol == 0x86DD:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            return None, "short_ipv6"
        total = 40 + int.from_bytes(ip[4:6], "big")
        if total == 40:
            return None, "ipv6_jumbogram_unsupported"
        source, destination = str(ip_address(ip[8:24])), str(ip_address(ip[24:40]))
        transport, body = ip[6], ip[40:total]
    else:
        return None, "non_ip"
    if transport not in {6, 17}:
        return None, "transport_or_extension_unsupported"
    minimum = 20 if transport == 6 else 8
    if len(body) < minimum:
        return None, "short_transport"
    sport, dport = struct.unpack_from("!HH", body)
    header_length = (body[12] >> 4) * 4 if transport == 6 else 8
    if header_length < minimum or len(body) < header_length:
        return None, "invalid_transport_header"
    proto = "tcp" if transport == 6 else "udp"
    hello = client_hello_ja3(body[header_length:]) if proto == "tcp" else None
    attempted_hello = proto == "tcp" and body[header_length:header_length + 1] == b"\x16"
    return ((source, sport, destination, dport, proto), total, hello, attempted_hello), None


@dataclass
class CaptureMetadata:
    sequences: dict
    fingerprints: dict
    fingerprint_times: dict
    report: dict


def extract_capture(path, connections, *, maximum_packets=5_000_000, sequence_limit=128):
    if not 4 <= sequence_limit <= 128 or maximum_packets < 1:
        raise ValueError("Invalid capture extraction limits")
    lookup = defaultdict(list)
    for event in connections:
        if not math.isfinite(event.duration_seconds) or event.duration_seconds < 0:
            raise ValueError("Connection duration must be finite and nonnegative")
        source, destination = str(ip_address(event.src_ip)), str(ip_address(event.dst_ip))
        key = (source, event.src_port, destination, event.dst_port, event.protocol)
        reverse = (destination, event.dst_port, source, event.src_port, event.protocol)
        identity = (event.flow_id, event.src_ip, event.dst_ip)
        lookup[key].append((event, identity, "orig"))
        lookup[reverse].append((event, identity, "resp"))
    sequences, fingerprints, fingerprint_times = {}, {}, {}
    counters = Counter()
    digest = sha256()
    latest = None
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        digest.update(header)
        magics = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                  b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError("Expected classic PCAP; PCAPNG requires conversion before extraction")
        endian, resolution = magics[header[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or link != 1:
            raise ValueError("Only PCAP v2.4 Ethernet captures are supported")
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Truncated PCAP packet header")
            digest.update(packet_header)
            sec, fraction, captured, original = struct.unpack(endian + "IIII", packet_header)
            if captured > min(snaplen, 16_777_216) or captured > original or fraction >= resolution:
                raise ValueError("Invalid PCAP packet lengths/timestamp")
            frame = stream.read(captured)
            if len(frame) != captured:
                raise ValueError("Truncated PCAP packet data")
            digest.update(frame)
            counters["packets_seen"] += 1
            if counters["packets_seen"] > maximum_packets:
                raise ValueError("Capture exceeds configured packet limit")
            timestamp = sec + fraction / resolution
            if latest is not None and timestamp < latest:
                counters["out_of_order_packets"] += 1
            latest = max(timestamp, latest or timestamp)
            if captured < original:
                counters["snaplen_truncated_packets"] += 1
            parsed, reason = packet_headers(frame)
            if parsed is None:
                counters[reason] += 1
                continue
            key, ip_bytes, hello, attempted = parsed
            candidates = [(event, identity, direction) for event, identity, direction in lookup.get(key, ())
                          if event.timestamp - 0.000001 <= timestamp <= event.timestamp + event.duration_seconds + 0.000001]
            if len(candidates) != 1:
                counters["ambiguous_packets" if candidates else "unmatched_packets"] += 1
                continue
            _, identity, direction = candidates[0]
            counters["matched_packets"] += 1
            sequence = sequences.setdefault(identity, [])
            if len(sequence) < sequence_limit:
                sequence.append({"ts": timestamp, "ip_bytes": ip_bytes, "direction": direction})
            else:
                counters["sequence_tail_not_retained"] += 1
            if hello and direction == "orig":
                fingerprint_times[identity] = max(timestamp, fingerprint_times.get(identity, timestamp))
                if identity in fingerprints and fingerprints[identity] != hello:
                    counters["conflicting_client_hellos"] += 1
                    fingerprints[identity] = None
                else:
                    fingerprints[identity] = hello
            elif attempted:
                counters["incomplete_or_unsupported_hello"] += 1
    return CaptureMetadata(sequences, fingerprints, fingerprint_times, {
        "extractor_version": VERSION, "capture_sha256": digest.hexdigest(), "counters": dict(counters),
        "payload_decrypted": False, "application_payload_retained": False,
        "ja3_scope": "complete cleartext ClientHello in one TCP segment; no TCP reassembly",
        "unsupported": ["PCAPNG", "non-Ethernet", "IP fragmentation/IPv6 extension chains", "QUIC fingerprint extraction"],
    })
