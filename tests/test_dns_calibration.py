from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.cli import main
from aegisflow.dns_calibration import (fit_candidate, evaluate_candidate, load_candidate, pipeline_evaluation,
                                      scored_metrics, gate_failures, write_new_json)
from aegisflow.dns_corpus import load_dns_corpus, read_manifest
from aegisflow.dns_model import DNSLabelledDomain, DNSNgramModel
from aegisflow.public_suffix import PublicSuffixList


class DNSCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "manifest.json"
        self.candidate_path = self.root / "candidate.json"
        self.manifest = {"schema_version": "drastha-dns-corpus-v1", "corpus_id": "unit-test-only",
                         "source_url": "https://example.test", "license": "synthetic-test",
                         "license_url": "https://example.test", "citation": "Synthetic unit tests",
                         "label_caveat": "Not real traffic", "split_seed": "test-v1", "sources": [],
                         "threshold_grid": [0.5, 0.9, 0.99],
                         "gates": {"maximum_fpr": 0.01, "minimum_recall": 0.7,
                                   "minimum_family_recall": 0.5, "minimum_positives": 10, "minimum_negatives": 10}}
        psl = b"com\nco.uk\ntest\n*.ck\n!www.ck\nblogspot.com\n"
        (self.root / "suffix.txt").write_bytes(psl)
        self.manifest["public_suffix_list"] = {"path": "suffix.txt", "sha256": sha256(psl).hexdigest()}
        for split, prefix in (("train", "zxq"), ("validation", "kvn"), ("test", "btp")):
            self.source(prefix, [f"{prefix}{i}random.test" for i in range(12)], 1, split)
        self.source("benign", [f"service{i}.example{i}.test" for i in range(100)], 0, "group-hash-60-20-20")
        self.save()

    def source(self, family, domains, label, split):
        data = ("\n".join(domains) + "\n").encode()
        name = family + ".txt"
        (self.root / name).write_bytes(data)
        entry = {"family": family, "label": label, "split": split, "path": name,
                 "records": len(domains), "sha256": sha256(data).hexdigest()}
        self.manifest["sources"].append(entry)
        return entry

    def save(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def candidate(self):
        candidate = fit_candidate(self.path, self.root)
        write_new_json(self.candidate_path, candidate)
        return candidate

    def test_only_train_is_fitted_and_only_validation_is_scored_during_selection(self):
        with (patch("aegisflow.dns_calibration.DNSNgramModel.train", wraps=DNSNgramModel.train) as fit,
              patch("aegisflow.dns_calibration.scored_metrics", wraps=scored_metrics) as score):
            candidate = self.candidate()
        self.assertEqual({row.split for row in fit.call_args.args[0]}, {"train"})
        self.assertTrue(all({r.split for r in call.args[0]} == {"validation"} for call in score.call_args_list))
        self.assertFalse(candidate["test_used_for_selection"])
        self.assertFalse(candidate["production_approved"])
        self.assertNotIn("test", candidate)

    def test_holdout_content_cannot_influence_selected_model_or_threshold(self):
        first = fit_candidate(self.path, self.root)
        self.manifest["sources"] = [entry for entry in self.manifest["sources"] if entry["family"] != "btp"]
        self.source("btp", [f"innocent-word{i}.test" for i in range(15)], 1, "test")
        self.save()
        second = fit_candidate(self.path, self.root)
        self.assertEqual(first["model"], second["model"])
        self.assertEqual(first["validation"], second["validation"])
        self.assertNotEqual(first["candidate_sha256"], second["candidate_sha256"])

    def test_exact_threshold_and_full_query_reach_upload_and_database_api(self):
        model = DNSNgramModel.train(load_dns_corpus(self.path, self.root)[1]["train"])
        model.payload.update(input_mode="full-query-v1", operating_threshold=0.9, research_status="not_approved")
        rows = [DNSLabelledDomain("abc.sub.example.test", 1, "attack", "test"),
                DNSLabelledDomain("normal.example.test", 0, "normal", "test")]
        repository = IncidentRepository(self.root / "eval.db")
        observed_inputs = []
        def predict(domain):
            observed_inputs.append(domain)
            return 0.95 if domain.startswith("abc.") else 0.8
        with patch.object(model, "predict_probability", side_effect=predict), patch.dict(os.environ, {
            "DRASTHA_DNS_MODEL": "nonexistent.json", "DRASTHA_INTERNAL_NETWORKS": "invalid"
        }):
            result = pipeline_evaluation(rows, model, repository)
        self.assertEqual(observed_inputs, [row.domain for row in rows])
        self.assertEqual(result["metrics"]["tp"], 1)
        self.assertEqual(result["metrics"]["fp"], 0)
        self.assertEqual(result["metrics"]["tn"], 1)
        self.assertEqual(result["quality"]["status"], "healthy")
        self.assertEqual(result["analysis_provenance"]["configuration"]["dns"]["dga_probability_threshold"], 0.9)
        response = TestClient(create_app(repository)).get("/api/analysis-runs/" + result["run_id"])
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertIsNone(report["evaluation"])
        self.assertEqual(report["analysis_provenance"], json.loads(json.dumps(result["analysis_provenance"])))
        self.assertEqual(report["alerts"][0]["evidence"][0]["comparison"], ">= 0.9")

    def test_frozen_holdout_pipeline_matches_classifier_and_leaves_artifact_unchanged(self):
        candidate = self.candidate()
        before = self.candidate_path.read_bytes()
        result = evaluate_candidate(self.candidate_path, self.path, self.root)
        self.assertTrue(result["upload_prediction_parity"])
        self.assertFalse(result["production_approved"])
        self.assertEqual(result["candidate_sha256"], candidate["candidate_sha256"])
        self.assertEqual(self.candidate_path.read_bytes(), before)

    def test_threshold_tampering_rejected_before_inference(self):
        candidate = self.candidate()
        candidate["model"]["operating_threshold"] = 0.1
        self.candidate_path.write_text(json.dumps(candidate))
        with patch("aegisflow.dns_calibration.pipeline_evaluation") as inference:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                evaluate_candidate(self.candidate_path, self.path, self.root)
            inference.assert_not_called()

    def test_changed_corpus_or_gate_rejected_for_frozen_candidate(self):
        self.candidate()
        self.manifest["gates"]["maximum_fpr"] = 1
        self.save()
        with self.assertRaisesRegex(ValueError, "differ from the frozen"):
            evaluate_candidate(self.candidate_path, self.path, self.root)

    def test_research_candidate_cannot_be_loaded_as_deployment_model(self):
        candidate = self.candidate()
        with self.assertRaisesRegex(ValueError, "not approved"):
            DNSNgramModel.load(self.candidate_path)
        naked = self.root / "model.json"
        naked.write_text(json.dumps(candidate["model"]))
        with self.assertRaisesRegex(ValueError, "not approved"):
            AnalysisSession.from_root(self.root, UPLOAD_DEMO, model_path=naked)

    def test_http_upload_cannot_activate_rejected_research_model(self):
        self.candidate()
        repository = IncidentRepository(self.root / "api.db")
        record = {"ts": 1800000000, "uid": "DNS1", "id.orig_h": "192.0.2.1",
                  "id.resp_h": "192.0.2.53", "proto": "udp", "query": "example.test"}
        with patch.dict(os.environ, {"DRASTHA_DNS_MODEL": str(self.candidate_path)}):
            response = TestClient(create_app(repository)).post("/api/replays/analyse",
                json={"filename": "traffic.jsonl", "content": json.dumps(record)})
        self.assertEqual(response.status_code, 422)
        self.assertIn("not approved", response.json()["detail"])
        self.assertEqual(repository.list_incidents(), [])

    def test_no_eligible_threshold_is_reported_as_failed_not_healthy(self):
        candidate = self.candidate()
        self.assertTrue(candidate["validation_gate_failures"])
        self.assertLess(candidate["model"]["operating_threshold"], 1)
        result = evaluate_candidate(self.candidate_path, self.path, self.root)
        self.assertFalse(result["dataset_gates_passed"])

    def test_metrics_include_misses_and_negative_denominator(self):
        rows = [DNSLabelledDomain(str(i), label, "family"+str(label), "test") for i, label in enumerate([1, 1, 0, 0])]
        result = scored_metrics(rows, [0.9, 0.1, 0.8, 0.2], 0.5)
        self.assertEqual({key: result[key] for key in ("tp", "fp", "fn", "tn")}, dict(tp=1, fp=1, fn=1, tn=1))
        self.assertEqual(result["fpr"], 0.5)
        self.assertAlmostEqual(result["score_diagnostics"]["brier"], 0.375)
        self.assertIn("fpr_wilson_upper_bound_exceeds_budget", gate_failures(result, self.manifest["gates"]))

    def test_pinned_source_tampering_is_rejected(self):
        (self.root / "zxq.txt").write_text("changed.test\n")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            load_dns_corpus(self.path, self.root)

    def test_domain_group_leakage_rejected_even_for_different_subdomains(self):
        self.source("more-train", ["a.same-domain.test"], 1, "train")
        self.source("more-test", ["b.same-domain.test"], 1, "test")
        self.save()
        with self.assertRaisesRegex(ValueError, "Domain-group leakage"):
            load_dns_corpus(self.path, self.root)

    def test_family_leakage_rejected(self):
        self.manifest["sources"][1]["family"] = "zxq"
        self.save()
        with self.assertRaisesRegex(ValueError, "family leakage"):
            load_dns_corpus(self.path, self.root)

    def test_duplicate_same_label_audited_not_counted_twice(self):
        self.source("dup", ["duplicate.test", "duplicate.test"], 1, "train")
        self.save()
        audit = load_dns_corpus(self.path, self.root)[2]
        self.assertEqual(audit["duplicate_same_label_rows"], 1)
        self.assertEqual(audit["raw_records"] - audit["unique_records"], 1)

    def test_invalid_domain_and_count_are_not_silently_dropped(self):
        self.source("invalid", ["https://invalid.test"], 1, "train")
        self.save()
        with self.assertRaisesRegex(ValueError, "Invalid DNS name"):
            load_dns_corpus(self.path, self.root)
        self.manifest["sources"][-1]["records"] = 2
        self.save()
        with self.assertRaisesRegex(ValueError, "record count mismatch"):
            load_dns_corpus(self.path, self.root)

    def test_path_escape_rejected(self):
        self.manifest["sources"][0]["path"] = "../escape.txt"
        self.save()
        with self.assertRaisesRegex(ValueError, "escapes data root"):
            load_dns_corpus(self.path, self.root)

    def test_malformed_grid_and_gates_rejected(self):
        original = deepcopy(self.manifest)
        for grid in ([0.5, 0.5], [1], [float("nan")], [True], [], [0.9, 0.5]):
            with self.subTest(grid=grid):
                self.manifest = deepcopy(original)
                self.manifest["threshold_grid"] = grid
                self.save()
                with self.assertRaises(ValueError):
                    read_manifest(self.path)
        self.manifest = deepcopy(original)
        self.manifest["gates"]["minimum_positives"] = 0
        self.save()
        with self.assertRaises(ValueError):
            read_manifest(self.path)

    def test_cli_create_only_outputs_preserve_inputs_and_existing_experiments(self):
        before = self.path.read_bytes()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["fit-dns-candidate", "--manifest", str(self.path), "--data-root", str(self.root),
                         "--candidate-output", str(self.path)])
        self.assertEqual(code, 2)
        self.assertEqual(self.path.read_bytes(), before)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["fit-dns-candidate", "--manifest", str(self.path), "--data-root", str(self.root),
                                   "--candidate-output", str(self.candidate_path)]), 0)
            self.assertEqual(main(["evaluate-dns-candidate", "--manifest", str(self.path), "--data-root", str(self.root),
                                   "--candidate", str(self.candidate_path), "--report-output", str(self.root/"result.json")]), 0)
        with self.assertRaises(FileExistsError):
            write_new_json(self.candidate_path, {})

    def test_checked_in_manifest_is_valid_and_family_holdouts_are_explicit(self):
        manifest, _ = read_manifest(ROOT / "data/manifests/umudga_dns_v1.json")
        by_split = {split: {s["family"] for s in manifest["sources"] if s["label"] and s["split"] == split}
                    for split in ("train", "validation", "test")}
        self.assertEqual(len(by_split["train"]), 8)
        self.assertEqual(by_split["test"], {"gozi", "locky"})
        self.assertFalse(by_split["train"] & by_split["validation"] | by_split["train"] & by_split["test"])

    def test_suffix_grouping_handles_country_private_wildcard_and_exception_rules(self):
        psl = PublicSuffixList("com\nco.uk\n*.ck\n!www.ck\nblogspot.com\n公司.cn\n")
        for domain, expected in {
            "a.example.co.uk": "example.co.uk", "b.another.co.uk": "another.co.uk",
            "a.tenant.blogspot.com": "tenant.blogspot.com", "a.b.c.ck": "b.c.ck",
            "a.www.ck": "www.ck", "a.b.unknown": "b.unknown", "co.uk": "co.uk",
            "WWW.tenant.公司.cn.": "tenant.xn--55qx5d.cn",
        }.items():
            with self.subTest(domain=domain):
                self.assertEqual(psl.registrable_domain(domain), expected)


if __name__ == "__main__":
    unittest.main()
