"""Portable checks for the committed Gate 2 evidence, without local raw PCAPs."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (
    "sih26145-gate2-flow-freeze-v1.json",
    "sih26145-gate2-metadata-freeze-v1.json",
    "sih26145-gate2-dga-freeze-v1.json",
    "sih26145-gate2-tls-freeze-v1.json",
    "sih26145-gate2-tls-freeze-v2.json",
)


class FrozenGate2EvidenceTests(unittest.TestCase):
    def test_committed_fixtures_and_labels_match_frozen_hashes(self):
        for name in MANIFESTS:
            with self.subTest(manifest=name):
                manifest = json.loads((ROOT / "data/manifests" / name).read_text(encoding="utf-8"))
                if "artifacts" in manifest:
                    artifacts = manifest["artifacts"]
                    for artifact in artifacts:
                        fixture = artifact.get("fixture")
                        if fixture:
                            self.assertEqual(sha256((ROOT / fixture).read_bytes()).hexdigest(),
                                             artifact["fixture_sha256"])
                        elif artifact.get("committed"):
                            self.assertEqual(sha256((ROOT / artifact["path"]).read_bytes()).hexdigest(),
                                             artifact["sha256"])
                else:
                    self.assertEqual(sha256((ROOT / manifest["fixture"]).read_bytes()).hexdigest(),
                                     manifest["fixture_sha256"])
                if "labels" in manifest:
                    self.assertEqual(sha256((ROOT / manifest["labels"]).read_bytes()).hexdigest(),
                                     manifest["labels_sha256"])
                self.assertFalse(manifest.get("inference_run_at_freeze", False))

    def test_no_injected_ground_truth_or_anomaly_scores(self):
        for name in MANIFESTS:
            manifest = json.loads((ROOT / "data/manifests" / name).read_text(encoding="utf-8"))
            fixtures = [item["fixture"] for item in manifest.get("artifacts", []) if "fixture" in item]
            fixtures.extend(item["path"] for item in manifest.get("artifacts", [])
                            if item.get("committed") and item["path"].endswith(".jsonl"))
            if "fixture" in manifest:
                fixtures.append(manifest["fixture"])
            for fixture in fixtures:
                with self.subTest(fixture=fixture):
                    rows = [json.loads(line) for line in (ROOT / fixture).read_text(encoding="utf-8").splitlines()]
                    self.assertTrue(rows)
                    self.assertTrue(all("ts" in row and "uid" in row for row in rows))
                    self.assertTrue(all(not any(key.startswith("evaluation_") for key in row)
                                        and "ml_evidence" not in row and "features" not in row
                                        for row in rows))
                    self.assertEqual([float(row["ts"]) for row in rows],
                                     sorted(float(row["ts"]) for row in rows))


if __name__ == "__main__":
    unittest.main()
