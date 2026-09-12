"""The SIH promotion decision must never ignore new-source failures."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_sih_final_gate import assess


class FinalGateTests(unittest.TestCase):
    def reports(self):
        release = {"passed": True, "release_id": "test", "verified_results": {"performance": {"records_per_second": 50}}}
        flow = {"passed": True, "totals": {"tp": 5, "fp": 0, "fn": 0, "tn": 1}}
        metadata = {"passed": True, "totals": {"tp": 3, "fp": 0, "fn": 0}}
        dga = {"quality_healthy": True, "totals": {"tp": 0, "fp": 2, "fn": 40, "tn": 38}}
        tls = {"quality_healthy": True, "measured_only": True, "tp_sessions": 0,
               "fp_sessions": 0, "fn_sessions": 6, "tn_sessions": 110,
               "feature_coverage": {"counts": {"derived": 16, "insufficient_evidence": 100}}}
        suites = {name: {"passed": True} for name in ("python", "frontend", "build")}
        return release, flow, metadata, dga, tls, suites

    def test_existing_demo_success_cannot_promote_failed_fresh_holdouts(self):
        report = assess(*self.reports())
        self.assertTrue(report["functional_prototype_verified"])
        self.assertFalse(report["fresh_source_evidence_complete"])
        self.assertFalse(report["release_promotion_allowed"])
        self.assertFalse(report["gates"]["fresh_published_dga_detection"])
        self.assertFalse(report["gates"]["fresh_measured_tls_positive"])

    def test_fresh_evidence_and_suites_are_required_separately(self):
        release, flow, metadata, dga, tls, suites = self.reports()
        dga["totals"].update(tp=38, fn=2, fp=0, tn=40)
        tls.update(tp_sessions=4, fn_sessions=2)
        report = assess(release, flow, metadata, dga, tls, suites)
        self.assertTrue(report["release_promotion_allowed"])
        suites["python"]["passed"] = False
        self.assertFalse(assess(release, flow, metadata, dga, tls, suites)["release_promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
