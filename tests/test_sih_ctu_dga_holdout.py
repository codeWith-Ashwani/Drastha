from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CTUDGAHoldoutTests(unittest.TestCase):
    def test_prediction_blind_fixture_matches_freeze(self):
        manifest = json.loads((ROOT / "data/manifests/sih26145-ctu-dga-holdout-freeze-v1.json")
                              .read_text(encoding="utf-8"))
        labels = ROOT / manifest["labels"]
        fixture = ROOT / manifest["fixture"]
        self.assertEqual(sha256(labels.read_bytes()).hexdigest(), manifest["labels_sha256"])
        self.assertEqual(sha256(fixture.read_bytes()).hexdigest(), manifest["fixture_sha256"])
        self.assertFalse(manifest["inference_run_at_freeze"])
        self.assertEqual(manifest["records"], 4000)
        self.assertEqual(manifest["class_counts"], {"benign": 2000, "dga": 2000})

    def test_fixture_is_distinct_balanced_and_label_only(self):
        rows = [json.loads(line) for line in
                (ROOT / "examples/sih26145_ctu_dga_holdout_v1.jsonl")
                .read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 4000)
        self.assertEqual(len({row["domain"] for row in rows}), 4000)
        self.assertEqual(sum(row["label"] == 0 for row in rows), 2000)
        self.assertEqual(sum(row["label"] == 1 for row in rows), 2000)
        self.assertTrue(all(set(row) == {"domain", "label", "source_class"} for row in rows))

    def test_failed_candidate_was_not_promoted(self):
        report = json.loads((ROOT / "output/sih_ctu_dga_holdout_audit.json")
                            .read_text(encoding="utf-8"))
        candidate = report["models"]["research_candidate"]
        self.assertFalse(candidate["passed"])
        self.assertFalse(report["promotion_eligible"])
        self.assertEqual(candidate["direct_metrics"]["recall"], 0.688)
        self.assertEqual(candidate["direct_metrics"]["fpr"], 0.001)
        self.assertEqual(candidate["direct_metrics"]["tp"], 1376)
        self.assertEqual(candidate["direct_metrics"]["fp"], 2)
        self.assertEqual(candidate["upload_metrics"]["quality"], "healthy")
        self.assertEqual(candidate["upload_metrics"]["rejected"], 0)
        self.assertEqual(
            tuple(candidate["direct_metrics"][key] for key in ("tp", "fp", "fn", "tn")),
            tuple(candidate["upload_metrics"][key] for key in ("tp", "fp", "fn", "tn")),
        )


if __name__ == "__main__":
    unittest.main()
