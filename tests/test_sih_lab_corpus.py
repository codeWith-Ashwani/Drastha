from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_sih_lab_corpus import VERSION, build, scenarios
from check_sih_lab_corpus import EXPECTED_BASELINE, audit


class SIHLabCorpusTests(unittest.TestCase):
    def test_checked_in_corpus_is_deterministic(self):
        generated = build(ROOT)
        self.assertEqual(27, len(generated))
        for path, expected in generated.items():
            self.assertTrue(path.is_file(), path)
            self.assertEqual(expected, path.read_bytes(), path)

    def test_manifest_has_separate_labels_and_safety_contract(self):
        import json
        manifest = json.loads((ROOT / "data" / "manifests" / f"{VERSION}.json").read_text())
        self.assertEqual(13, len(manifest["artifacts"]))
        self.assertEqual("offline_semantic_equivalent", manifest["provenance_tier"])
        self.assertFalse(manifest["safety"]["active_network_transmission"])
        self.assertFalse(manifest["safety"]["attack_tools_executed"])
        self.assertFalse(manifest["safety"]["ground_truth_in_telemetry"])
        self.assertTrue(all(entry["labels"]["path"].endswith(".labels.json") for entry in manifest["artifacts"]))

    def test_actual_shared_analysis_path_preserves_audited_baseline(self):
        report = audit(ROOT)
        self.assertTrue(report["passed"], report["gates"])
        self.assertEqual(EXPECTED_BASELINE, report["baseline"]["expected_counts"])
        self.assertEqual(392, report["integrity"]["records"])
        self.assertTrue(all(report["gates"].values()))
        self.assertEqual(13, len(scenarios()))


if __name__ == "__main__":
    unittest.main()
