import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.c2 import C2BeaconDetector, C2Config
from aegisflow.models import EncryptedSessionMetadata, NetworkEvent


def connection(index, timestamp, total_bytes=500, destination="203.0.113.77"):
    return NetworkEvent(
        timestamp=timestamp,
        flow_id=f"flow-{index}",
        src_ip="10.0.0.44",
        dst_ip=destination,
        src_port=50000 + index,
        dst_port=443,
        protocol="tcp",
        outbound_bytes=180,
        inbound_bytes=total_bytes - 180,
        connection_state="SF",
    )


class C2DetectorTests(unittest.TestCase):
    def test_periodic_stable_connections_alert(self):
        detector = C2BeaconDetector(C2Config(minimum_connections=6))
        alerts = []
        for index in range(6):
            alerts.extend(detector.process(connection(index, 1000 + index * 10)))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "periodic_beacon")
        self.assertTrue(any(item.name == "interval_variation" for item in alerts[0].evidence))

    def test_irregular_scheduled_traffic_does_not_alert(self):
        detector = C2BeaconDetector(C2Config(minimum_connections=6))
        alerts = []
        for index, timestamp in enumerate((1000, 1004, 1025, 1030, 1080, 1090)):
            alerts.extend(detector.process(connection(index, timestamp)))
        self.assertEqual(alerts, [])

    def test_variable_transfer_sizes_do_not_alert(self):
        detector = C2BeaconDetector(C2Config(minimum_connections=6))
        alerts = []
        for index, size in enumerate((200, 2000, 300, 3500, 500, 5000)):
            alerts.extend(detector.process(connection(index, 1000 + index * 10, size)))
        self.assertEqual(alerts, [])

    def test_allowlisted_periodic_service_is_suppressed(self):
        detector = C2BeaconDetector(
            C2Config(minimum_connections=6), allowlisted_destinations={"203.0.113.77"}
        )
        alerts = []
        for index in range(6):
            alerts.extend(detector.process(connection(index, 1000 + index * 10)))
        self.assertEqual(alerts, [])

    def test_fingerprint_is_context_not_trigger(self):
        metadata = EncryptedSessionMetadata(
            timestamp=1000,
            flow_id="flow-0",
            src_ip="10.0.0.44",
            dst_ip="203.0.113.77",
            transport="tls",
            client_fingerprint="rare-ja3",
        )
        detector = C2BeaconDetector(
            C2Config(minimum_connections=6), encrypted_metadata={"flow-0": (metadata, 0.9)}
        )
        self.assertEqual(detector.process(connection(0, 1000)), [])

    def test_tls_metadata_enriches_timing_alert(self):
        metadata = {}
        for index in range(6):
            item = EncryptedSessionMetadata(
                timestamp=1000 + index * 10,
                flow_id=f"flow-{index}",
                src_ip="10.0.0.44",
                dst_ip="203.0.113.77",
                transport="tls",
                server_name="control.example",
                client_fingerprint="demo-ja3",
                established=True,
            )
            metadata[item.flow_id] = (item, 0.1)
        detector = C2BeaconDetector(C2Config(minimum_connections=6), encrypted_metadata=metadata)
        alerts = []
        for index in range(6):
            alerts.extend(detector.process(connection(index, 1000 + index * 10)))
        names = {item.name for item in alerts[0].evidence}
        self.assertIn("encrypted_metadata_anomaly_score", names)
        self.assertIn("observed_client_fingerprints", names)


if __name__ == "__main__":
    unittest.main()
