import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.exfiltration import ExfiltrationConfig, ExfiltrationDetector
from aegisflow.context_policy import EndpointRule
from aegisflow.models import NetworkEvent


def flow(index, timestamp, destination, outbound, inbound):
    return NetworkEvent(
        timestamp=timestamp,
        flow_id=f"flow-{index}",
        src_ip="10.0.0.44",
        dst_ip=destination,
        src_port=50000 + index,
        dst_port=443,
        protocol="tcp",
        outbound_bytes=outbound,
        inbound_bytes=inbound,
        connection_state="SF",
    )


class ExfiltrationDetectorTests(unittest.TestCase):
    def detector(self, approved=None):
        return ExfiltrationDetector(
            ExfiltrationConfig(
                minimum_flows=3,
                minimum_outbound_bytes=1_000_000,
                minimum_outbound_ratio=8,
                baseline_multiplier=4,
            ),
            approved_backup_destinations=approved,
        )

    def seed_baseline(self, detector):
        for index in range(5):
            detector.process(flow(index, 1000 + index * 10, f"192.0.2.{index}", 10_000, 5_000))

    def test_outbound_volume_anomaly_alerts(self):
        detector = self.detector()
        self.seed_baseline(detector)
        alerts = []
        for index in range(3):
            alerts.extend(detector.process(
                flow(10 + index, 1100 + index * 10, "198.51.100.88", 500_000, 1_000)
            ))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "outbound_volume_anomaly")
        self.assertTrue(any(item.name == "outbound_to_inbound_ratio" for item in alerts[0].evidence))

    def test_extreme_single_flow_asymmetry_alerts_without_a_baseline(self):
        detector = self.detector()
        alerts = detector.process(flow(
            99, 1200, "203.0.113.120", 18_500_000, 42_000
        ))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "outbound_volume_anomaly")

    def test_extreme_multiflow_asymmetry_alerts_without_a_baseline(self):
        detector = self.detector()
        alerts = []
        for index in range(5):
            alerts.extend(detector.process(flow(
                index, 1200 + index * 8, "203.0.113.220",
                3_200_000 + index * 120_000, 9_000 + index * 500,
            )))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "outbound_volume_anomaly")

    def test_approved_backup_does_not_alert(self):
        detector = self.detector({"198.51.100.88"})
        self.seed_baseline(detector)
        alerts = []
        for index in range(3):
            alerts.extend(detector.process(
                flow(10 + index, 1100 + index * 10, "198.51.100.88", 2_000_000, 1_000)
            ))
        self.assertEqual(alerts, [])

    def test_exact_approved_bulk_endpoint_is_suppressed(self):
        detector = ExfiltrationDetector(
            ExfiltrationConfig(),
            approved_bulk_transfer_endpoints=(EndpointRule(
                src_ip="10.0.0.44", dst_ip="198.51.100.88", dst_port=443,
                protocol="tcp", purpose="approved backup",
            ),),
        )
        alerts = detector.process(flow(
            99, 1200, "198.51.100.88", 18_500_000, 42_000
        ))
        self.assertEqual(alerts, [])
        self.assertEqual(detector.context_suppressed_records, 1)

    def test_untrusted_backup_claim_does_not_suppress_exfiltration(self):
        detector = self.detector()
        item = replace(
            flow(99, 1200, "203.0.113.120", 18_500_000, 42_000),
            raw={"ml_evidence": {"approved_backup": True}},
        )
        self.assertEqual(
            [alert.subtype for alert in detector.process(item)],
            ["outbound_volume_anomaly"],
        )

    def test_balanced_download_does_not_alert(self):
        detector = self.detector()
        self.seed_baseline(detector)
        alerts = []
        for index in range(3):
            alerts.extend(detector.process(
                flow(10 + index, 1100 + index * 10, "198.51.100.88", 500_000, 500_000)
            ))
        self.assertEqual(alerts, [])

    def test_baseline_and_windows_survive_detector_restart(self):
        first_process = self.detector()
        self.seed_baseline(first_process)

        restarted_process = self.detector()
        restarted_process.restore_state(first_process.export_state())
        alerts = []
        for index in range(3):
            alerts.extend(restarted_process.process(
                flow(10 + index, 1100 + index * 10, "198.51.100.88", 500_000, 1_000)
            ))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "outbound_volume_anomaly")


if __name__ == "__main__":
    unittest.main()
