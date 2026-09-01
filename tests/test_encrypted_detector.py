import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.encrypted import EncryptedSessionAnomalyDetector
from aegisflow.models import EncryptedSessionMetadata


def session(index, *, packet_anomaly=0.88, timing_anomaly=0.84, prevalence=0.002):
    return EncryptedSessionMetadata(
        timestamp=1000 + index * 5,
        flow_id=f"tls-{index}",
        src_ip="10.0.0.70",
        dst_ip="203.0.113.90",
        transport="tls",
        version="TLSv1.3",
        client_fingerprint="t13-demo-ja4",
        established=True,
        raw={"features": {
            "ja4_prevalence": prevalence,
            "packet_size_sequence_anomaly": packet_anomaly,
            "timing_sequence_anomaly": timing_anomaly,
        }},
    )


class EncryptedSessionAnomalyDetectorTests(unittest.TestCase):
    def test_requires_repeated_rare_fingerprint_and_sequence_anomalies(self):
        detector = EncryptedSessionAnomalyDetector()
        alerts = []
        for index in range(4):
            alerts.extend(detector.process(session(index)))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "encrypted_session_metadata_anomaly")

    def test_rare_fingerprint_alone_does_not_alert(self):
        detector = EncryptedSessionAnomalyDetector()
        alerts = []
        for index in range(4):
            alerts.extend(detector.process(session(
                index, packet_anomaly=0.1, timing_anomaly=0.1
            )))
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
