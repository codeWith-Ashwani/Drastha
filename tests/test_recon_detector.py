import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.recon import ReconConfig, ReconDetector
from aegisflow.models import NetworkEvent


def event(ts: float, uid: str, dst_ip: str, dst_port: int, src_ip: str = "10.0.0.50") -> NetworkEvent:
    return NetworkEvent(
        timestamp=ts, flow_id=uid, src_ip=src_ip, dst_ip=dst_ip,
        src_port=50000, dst_port=dst_port, protocol="tcp",
        connection_state="S0", source="test",
    )


class ReconDetectorTests(unittest.TestCase):
    def test_vertical_port_scan_emits_evidence_rich_alert(self):
        detector = ReconDetector(ReconConfig(
            window_seconds=10, unique_port_threshold=4,
            unique_host_threshold=10, cooldown_seconds=30,
        ))
        alerts = []
        for index, port in enumerate((21, 22, 23, 80)):
            alerts.extend(detector.process(event(index, f"C{index}", "10.0.0.8", port)))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.subtype, "vertical_port_scan")
        self.assertEqual(alert.dst_ip, "10.0.0.8")
        self.assertGreaterEqual(len(alert.evidence), 2)
        self.assertTrue(alert.limitations)

    def test_horizontal_host_scan(self):
        detector = ReconDetector(ReconConfig(
            window_seconds=10, unique_port_threshold=10,
            unique_host_threshold=4, cooldown_seconds=30,
        ))
        alerts = []
        for index in range(4):
            alerts.extend(detector.process(event(index, f"H{index}", f"10.0.1.{index + 1}", 443)))
        self.assertEqual([alert.subtype for alert in alerts], ["horizontal_host_scan"])

    def test_combined_host_and_port_fanout(self):
        detector = ReconDetector(ReconConfig(
            window_seconds=10, unique_port_threshold=5,
            unique_host_threshold=5, cooldown_seconds=30,
        ))
        alerts = []
        ports = (22, 23, 25, 53, 80, 110)
        for index, port in enumerate(ports):
            alerts.extend(detector.process(event(
                index * 0.2, f"M{index}", f"10.0.2.{index % 4 + 1}", port
            )))
        self.assertEqual([alert.subtype for alert in alerts], ["multi_host_port_scan"])
        self.assertIsNone(alerts[0].dst_ip)

    def test_benign_contacts_do_not_alert(self):
        detector = ReconDetector(ReconConfig(
            window_seconds=10, unique_port_threshold=4, unique_host_threshold=4,
        ))
        alerts = []
        for index in range(3):
            alerts.extend(detector.process(event(index, f"B{index}", "10.0.0.8", 443)))
        self.assertEqual(alerts, [])

    def test_old_contacts_expire_from_window(self):
        detector = ReconDetector(ReconConfig(
            window_seconds=2, unique_port_threshold=3, unique_host_threshold=10,
        ))
        alerts = []
        alerts.extend(detector.process(event(0, "C1", "10.0.0.8", 21)))
        alerts.extend(detector.process(event(1, "C2", "10.0.0.8", 22)))
        alerts.extend(detector.process(event(4, "C3", "10.0.0.8", 23)))
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
