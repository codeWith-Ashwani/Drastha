from hashlib import sha256
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from aegisflow.dns_corpus import digest  # noqa: E402
from evaluate_extrahop_dga import sample_source  # noqa: E402


class ExternalDGASprint30Tests(unittest.TestCase):
    def test_deterministic_sample_filters_unsupported_and_known_overlap(self):
        contract = {"records_per_label": 1000, "oversample_hash_fraction": 0.1,
                    "seed": "unit-external-sample"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json.gz"
            with gzip.open(path, "wt", encoding="utf-8", newline="\n") as stream:
                stream.write("# test source\n")
                for label, threat in ((0, "benign"), (1, "dga")):
                    for index in range(15000):
                        stream.write(json.dumps({"domain": f"{threat}{index}",
                                                 "threat": threat}) + "\n")
                stream.write(json.dumps({"domain": "bad_name", "threat": "benign"}) + "\n")
            first, audit = sample_source(path, contract, {"dga1"})
            second, repeated = sample_source(path, contract, {"dga1"})
        self.assertEqual(first, second)
        self.assertEqual(audit, repeated)
        self.assertEqual({0: 1000, 1: 1000},
                         {label: sum(row.label == label for row in first) for label in (0, 1)})
        self.assertEqual(2000, audit["selected_unique_domains"])
        self.assertEqual(1, audit["unsupported_dns_host_labels_excluded"])
        self.assertEqual(1, audit["umudga_core_overlaps_excluded"])
        self.assertNotIn("dga1", {row.domain for row in first})

    def test_structurally_invalid_source_fails_with_line_number(self):
        contract = {"records_per_label": 1000, "oversample_hash_fraction": 0.1,
                    "seed": "unit-external-sample"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as stream:
                stream.write('{"domain":"abc"}\n')
            with self.assertRaisesRegex(ValueError, "line 1"):
                sample_source(path, contract, set())

    def test_checked_in_external_report_is_bound_complete_and_non_promotable(self):
        manifest_path = ROOT / "data/manifests/extrahop_dga_v1.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        report = json.loads((ROOT / "output/sprint30_extrahop_dga_evaluation.json").read_text())
        self.assertEqual(sha256(manifest_bytes).hexdigest(), report["external_manifest_sha256"])
        self.assertEqual(manifest["source"]["sha256"], report["source_sha256"])
        self.assertEqual("95003671bc7117b96e5b6fddbb39e067f9a5872231affed592a33d162281cb6a",
                         report["candidate_sha256"])
        self.assertEqual(16246006, report["sample_audit"]["source_records"])
        self.assertEqual(2035, report["sample_audit"]["unsupported_dns_host_labels_excluded"])
        self.assertEqual(36379, report["sample_audit"]["umudga_core_overlaps_excluded"])
        self.assertEqual(40000, report["sample_audit"]["selected_unique_domains"])
        self.assertEqual({"tp": 12671, "fp": 1359, "fn": 7329, "tn": 18641},
                         {key: report["metrics"][key] for key in ("tp", "fp", "fn", "tn")})
        self.assertEqual(5, len(report["upload_analysis"]["chunks"]))
        self.assertEqual("healthy", report["upload_analysis"]["quality"]["status"])
        self.assertEqual(40000, report["upload_analysis"]["quality"]["records_accepted"])
        self.assertEqual(0, report["upload_analysis"]["quality"]["records_rejected"])
        self.assertTrue(report["upload_prediction_parity"])
        self.assertFalse(report["dataset_numeric_gates_passed"])
        self.assertEqual(report["report_sha256"],
                         digest({key: value for key, value in report.items()
                                 if key != "report_sha256"}))
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["production_approved"])


if __name__ == "__main__":
    unittest.main()
