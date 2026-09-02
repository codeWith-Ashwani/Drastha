import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.evaluation_scoring import score_ground_truth
from aegisflow.models import Alert


def alert(alert_id, subtype, flow_ids):
    return Alert(
        alert_id=alert_id, detector_id="test", detector_version="1",
        threat_type="test", subtype=subtype, confidence=0.9, severity="high",
        window_start=1, window_end=2, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        flow_ids=tuple(flow_ids), evidence=(),
    )


def record(uid, label, threat_class, src, dst, port=443, service="ssl"):
    return {
        "uid": uid, "evaluation_label": label,
        "evaluation_threat_class": threat_class,
        "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port,
        "service": service,
    }


class EvaluationScoringTests(unittest.TestCase):
    def test_scenario_metrics_include_tp_fp_fn_tn_and_rates(self):
        records = [
            record("scan-1", "attack", "reconnaissance_port_scan", "10.0.0.1", "10.0.0.8"),
            record("scan-2", "attack", "reconnaissance_port_scan", "10.0.0.1", "10.0.0.8"),
            record("c2-1", "attack", "botnet_c2_beaconing", "10.0.0.2", "203.0.113.8"),
            record("benign-1", "benign", "benign", "10.0.0.3", "203.0.113.9"),
            record("false-1", "benign", "benign", "10.0.0.4", "203.0.113.10"),
        ]
        alerts = [
            alert("a1", "multi_host_port_scan", ("scan-1", "scan-2")),
            alert("a2", "periodic_beacon", ("c2-1",)),
            alert("a3", "periodic_beacon", ("false-1",)),
        ]
        report = score_ground_truth(records, alerts)
        self.assertIsNotNone(report)
        self.assertEqual(report["true_positive"], 2)
        self.assertEqual(report["false_positive"], 1)
        self.assertEqual(report["false_negative"], 0)
        self.assertEqual(report["true_negative"], 1)
        self.assertEqual(report["precision"], 0.6667)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["f1_score"], 0.8)
        self.assertEqual(report["false_positive_rate"], 0.5)

    def test_no_evaluation_fields_returns_none(self):
        self.assertIsNone(score_ground_truth([{"uid": "one"}], []))


if __name__ == "__main__":
    unittest.main()
