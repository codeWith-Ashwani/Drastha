import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.health import ReplayHealth
from aegisflow.models import NetworkEvent


def event(ts):
    return NetworkEvent(ts, f"C{ts}", "10.0.0.1", "10.0.0.2", 50000, 443, "tcp")


class ReplayHealthTests(unittest.TestCase):
    def test_reports_event_span_rate_and_out_of_order_count(self):
        health = ReplayHealth()
        health.start()
        health.record_event(event(10.0))
        health.record_event(event(12.0))
        health.record_event(event(11.0))
        health.finish()
        report = health.to_dict()
        self.assertEqual(report["events_processed"], 3)
        self.assertEqual(report["event_time_span_seconds"], 2.0)
        self.assertEqual(report["out_of_order_events"], 1)
        self.assertGreater(report["processing_events_per_second"], 0)
        self.assertEqual(report["capture_loss_visibility"], "not_provided_by_conn_log")


if __name__ == "__main__":
    unittest.main()

