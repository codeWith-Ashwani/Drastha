import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.ddos import DDoSConfig, DDoSDetector
from aegisflow.models import NetworkEvent


def event(ts, uid, src, dst, protocol, state="S0", packets=1, bytes_sent=0):
    return NetworkEvent(
        timestamp=ts, flow_id=uid, src_ip=src, dst_ip=dst,
        src_port=50000, dst_port=443 if protocol == "tcp" else 53,
        protocol=protocol, connection_state=state,
        outbound_packets=packets, outbound_bytes=bytes_sent, source="test",
    )


class DDoSDetectorTests(unittest.TestCase):
    def test_syn_flood(self):
        detector = DDoSDetector(DDoSConfig(
            window_seconds=5, syn_attempt_threshold=5,
            min_incomplete_ratio=0.8, udp_packet_threshold=500,
        ))
        alerts = []
        for index in range(5):
            alerts.extend(detector.process(event(
                index * 0.2, f"S{index}", "203.0.113.10",
                "10.0.0.8", "tcp",
            )))
        self.assertEqual([alert.subtype for alert in alerts], ["syn_flood"])
        self.assertEqual(alerts[0].severity, "high")
        self.assertGreaterEqual(len(alerts[0].evidence), 3)
        self.assertTrue(any(
            item.name == "target_port_concentration" for item in alerts[0].evidence
        ))

    def test_high_source_entropy_is_labelled_as_distributed_source_syn_flood(self):
        detector = DDoSDetector(DDoSConfig(
            window_seconds=5, syn_attempt_threshold=5,
            min_incomplete_ratio=0.8, udp_packet_threshold=500,
        ))
        alerts = []
        for index in range(5):
            alerts.extend(detector.process(event(
                index * 0.2, f"E{index}", f"198.51.100.{index + 1}",
                "10.0.0.8", "tcp",
            )))
        self.assertEqual(
            [alert.subtype for alert in alerts], ["distributed_source_syn_flood"]
        )

    def test_port_fanout_is_not_misclassified_as_syn_flood(self):
        detector = DDoSDetector(DDoSConfig(
            window_seconds=5, syn_attempt_threshold=5,
            min_incomplete_ratio=0.8, udp_packet_threshold=500,
        ))
        alerts = []
        for index, port in enumerate((21, 22, 23, 25, 53)):
            item = event(index * 0.2, f"P{index}", "203.0.113.10", "10.0.0.8", "tcp")
            item = __import__("dataclasses").replace(item, dst_port=port)
            alerts.extend(detector.process(item))
        self.assertEqual(alerts, [])

    def test_completed_tcp_connections_do_not_trigger_syn_flood(self):
        detector = DDoSDetector(DDoSConfig(
            syn_attempt_threshold=5, min_incomplete_ratio=0.8,
            udp_packet_threshold=500,
        ))
        alerts = []
        for index in range(5):
            alerts.extend(detector.process(event(
                index * 0.2, f"C{index}", "203.0.113.10", "10.0.0.8", "tcp", state="SF",
            )))
        self.assertEqual(alerts, [])

    def test_udp_flood_uses_packet_volume(self):
        detector = DDoSDetector(DDoSConfig(
            syn_attempt_threshold=10, udp_packet_threshold=500,
        ))
        alerts = []
        alerts.extend(detector.process(event(0, "U1", "198.51.100.1", "10.0.0.9", "udp", packets=300, bytes_sent=24000)))
        alerts.extend(detector.process(event(1, "U2", "198.51.100.2", "10.0.0.9", "udp", packets=300, bytes_sent=24000)))
        self.assertEqual([alert.subtype for alert in alerts], ["udp_flood"])
        self.assertEqual(alerts[0].dst_ip, "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
