from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.benchmark import load_corpus, run_benchmark, VERSION
from aegisflow.benchmark_data import ctu13_records, prepare_dataset, validate_units
from aegisflow.benchmark_metrics import metrics, score_units
from aegisflow.cli import main
from aegisflow.dns_model import DNSLabelledDomain, DNSNgramModel, validate_leakage_safe_split


def fixture():
    records = [{"ts": 1000+i*.1, "uid": f"scan{i}", "id.orig_h": "198.51.100.1",
                "id.resp_h": "10.0.0.2", "id.orig_p": 50000, "id.resp_p": 100+i, "proto": "tcp",
                "conn_state": "S0"} for i in range(25)]
    units = [{"unit_id": "scan", "flow_ids": [r["uid"] for r in records], "label": "attack",
              "expected_classes": ["reconnaissance_port_scan"]}]
    for i in range(5):
        records.append({"ts": 1100+i, "uid": f"benign{i}", "id.orig_h": f"10.0.0.{i+10}",
                        "id.resp_h": "198.51.100.2", "proto": "tcp", "id.resp_p": 443, "conn_state": "SF"})
        units.append({"unit_id": f"benign{i}", "flow_ids": [f"benign{i}"], "label": "benign", "expected_classes": []})
    return records, units


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        records, units = fixture()
        self.entry = self.artifact("sample", records, units)
        self.manifest = {"schema_version": VERSION, "corpus_id": "synthetic-test", "internal_cidrs": ["10.0.0.0/8"],
                         "artifacts": [self.entry]}
        self.path = self.root / "manifest.json"
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def artifact(self, name, records, units, split="test"):
        text = "\n".join(map(json.dumps, records))
        payload = json.dumps({"units": units})
        (self.root / (name+".jsonl")).write_text(text, encoding="utf-8")
        (self.root / (name+".labels.json")).write_text(payload, encoding="utf-8")
        return {"id": name, "capture_id": name, "group_ids": ["family:"+name], "split": split,
                "format": "zeek-jsonl", "origin": {"kind": "synthetic"}, "path": name+".jsonl",
                "sha256": sha256((self.root / (name+".jsonl")).read_bytes()).hexdigest(), "labels": {"path": name+".labels.json",
                "sha256": sha256((self.root / (name+".labels.json")).read_bytes()).hexdigest()}}

    def test_shared_analysis_persistence_and_actual_api_readback(self):
        repository = IncidentRepository(self.root / "eval.db")
        result = run_benchmark(self.path, data_root=self.root, repository=repository)
        self.assertEqual(result["pooled_binary_alert_coverage"]["tp"], 1)
        self.assertEqual(result["pooled_binary_alert_coverage"]["tn"], 5)
        self.assertEqual(result["pooled_binary_alert_coverage"]["fp"], 0)
        run = result["runs"][0]
        self.assertEqual(run["quality"]["status"], "healthy")
        self.assertEqual(run["findings"], 1)
        self.assertIsNone(run["analysis_provenance"]["dns_model_sha256"])
        response = TestClient(create_app(repository)).get("/api/analysis-runs/" + run["run_id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["benchmark"]["scores"], run["scores"])
        self.assertIsNone(response.json()["evaluation"])

    def test_actual_cli_and_read_only_inputs(self):
        before = {p.name: sha256(p.read_bytes()).hexdigest() for p in self.root.iterdir()}
        with redirect_stdout(io.StringIO()):
            code = main(["evaluate-corpus", "--manifest", str(self.path), "--data-root", str(self.root),
                         "--report-output", str(self.root / "report.json")])
        self.assertEqual(code, 0)
        for name, digest in before.items():
            self.assertEqual(sha256((self.root/name).read_bytes()).hexdigest(), digest)

    def test_cli_refuses_to_overwrite_corpus_input(self):
        path = self.root / self.entry["path"]
        before = path.read_bytes()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["evaluate-corpus", "--manifest", str(self.path), "--data-root", str(self.root),
                         "--report-output", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(path.read_bytes(), before)

    def test_checksum_tampering_fails_before_inference(self):
        (self.root / self.entry["path"]).write_text("tampered")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            run_benchmark(self.path, data_root=self.root)

    def test_sidecar_checksum_is_verified(self):
        self.entry["labels"]["sha256"] = "0"*64
        self.save()
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            load_corpus(self.path, self.root)

    def test_group_leakage_is_rejected(self):
        second = deepcopy(self.entry)
        second.update(id="copy", split="train")
        self.manifest["artifacts"].append(second)
        self.save()
        with self.assertRaisesRegex(ValueError, "leakage"):
            load_corpus(self.path, self.root)

    def test_renamed_uid_does_not_hide_cross_split_duplicate(self):
        records, units = fixture()
        for record in records:
            record["uid"] += "copy"
            record["timestamp"] = str(record.pop("ts"))
            record["duration"] = 0
        for unit in units:
            unit["flow_ids"] = [uid+"copy" for uid in unit["flow_ids"]]
        self.manifest["artifacts"].append(self.artifact("another", records, units, "train"))
        self.save()
        with self.assertRaisesRegex(ValueError, "Duplicate normalized telemetry"):
            load_corpus(self.path, self.root)

    def test_duplicate_capture_hash_is_rejected(self):
        second = deepcopy(self.entry)
        second.update(id="copy", capture_id="copy", group_ids=["copy"])
        self.manifest["artifacts"].append(second)
        self.save()
        with self.assertRaisesRegex(ValueError, "Duplicate capture content"):
            load_corpus(self.path, self.root)

    def test_manifest_path_escape_rejected(self):
        self.entry["path"] = "../outside.jsonl"
        self.save()
        with self.assertRaisesRegex(ValueError, "escapes data root"):
            load_corpus(self.path, self.root)

    def test_external_artifact_requires_provenance(self):
        self.entry["origin"] = {"kind": "external"}
        self.save()
        with self.assertRaisesRegex(ValueError, "External data requires"):
            load_corpus(self.path, self.root)

    def test_selected_split_must_exist(self):
        with self.assertRaisesRegex(ValueError, "No artifacts"):
            run_benchmark(self.path, data_root=self.root, split="validation")

    def test_environment_does_not_inject_demo_model_policy_or_networks(self):
        with patch.dict(os.environ, {"DRASTHA_DNS_MODEL": "missing.json", "DRASTHA_CONTEXT_POLICY": "missing.json",
                                     "DRASTHA_INTERNAL_NETWORKS": "invalid", "DRASTHA_ANALYSIS_PROFILE": "upload-demo"}):
            result = run_benchmark(self.path, data_root=self.root)
        configuration = result["runs"][0]["analysis_provenance"]["configuration"]
        self.assertEqual(configuration["feature_mode"], "derived")
        self.assertEqual(configuration["internal_cidrs"], ("10.0.0.0/8",))

    def test_inline_labels_and_supplied_scores_do_not_reach_inference(self):
        records, units = fixture()
        baseline = run_benchmark(self.path, data_root=self.root)
        for record in records:
            record.update(evaluation_label="benign", evaluation_threat_class="dns_tunnelling",
                          ml_evidence={"ja4": "fake", "packet_size_sequence_anomaly": 1}, features={"query_name": "fake"})
        self.manifest["artifacts"] = [self.artifact("sample", records, units)]
        self.save()
        poisoned = run_benchmark(self.path, data_root=self.root)
        self.assertEqual(baseline["runs"][0]["scores"], poisoned["runs"][0]["scores"])
        self.assertEqual(baseline["runs"][0]["observed_subtypes"], poisoned["runs"][0]["observed_subtypes"])

    def test_order_quality_is_not_hidden_by_detector_sorting(self):
        records, units = fixture()
        records[1], records[2] = records[2], records[1]
        self.manifest["artifacts"] = [self.artifact("sample", records, units)]
        self.save()
        result = run_benchmark(self.path, data_root=self.root)
        self.assertEqual(result["runs"][0]["quality"]["status"], "degraded")
        self.assertEqual(result["runs"][0]["quality"]["out_of_order_records"], 1)

    def test_rejected_labelled_record_retained_in_actual_pipeline_score(self):
        records, units = fixture()
        records.append({"uid": "bad", "ts": 1200, "id.orig_h": "invalid-ip", "id.resp_h": "10.0.0.2", "proto": "tcp"})
        units.append({"unit_id": "rejected-attack", "flow_ids": ["bad"], "label": "attack", "expected_classes": ["any_attack"]})
        self.manifest["artifacts"] = [self.artifact("sample", records, units)]
        self.save()
        result = run_benchmark(self.path, data_root=self.root)
        self.assertEqual(result["runs"][0]["quality"]["records_rejected"], 1)
        self.assertEqual(result["pooled_binary_alert_coverage"]["fn"], 1)

    def test_manifest_pinned_record_count_is_enforced(self):
        self.entry["expected_records"] = 999
        self.save()
        with self.assertRaisesRegex(ValueError, "record count"):
            load_corpus(self.path, self.root)

    def test_bad_manifest_cli_fails_without_traceback(self):
        self.path.write_text("[]")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
            code = main(["evaluate-corpus", "--manifest", str(self.path), "--data-root", str(self.root),
                         "--report-output", str(self.root / "report.json")])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", errors.getvalue())

    def test_capture_sessions_are_isolated(self):
        records, units = fixture()
        for record in records:
            record["ts"] += 10000
        self.manifest["artifacts"].append(self.artifact("second", records, units))
        self.save()
        report = run_benchmark(self.path, data_root=self.root)
        self.assertEqual([r["scores"]["binary_alert_coverage"]["tp"] for r in report["runs"]], [1, 1])

    def test_model_lineage_must_reference_audited_training_groups(self):
        self.manifest["dns_model"] = {"training_group_ids": ["family:test"], "path": "model.json", "sha256": "0"*64}
        self.save()
        with self.assertRaisesRegex(ValueError, "training lineage"):
            run_benchmark(self.path, data_root=self.root)


class ScoringTests(unittest.TestCase):
    def test_wrong_subtype_is_false_negative_and_false_positive(self):
        units = [{"unit_id": "scan", "flow_ids": ["a"], "label": "attack", "expected_classes": ["reconnaissance_port_scan"]}]
        result = score_units(units, [{"alert_id": "x", "flow_ids": ["a"], "subtype": "periodic_beacon"}], {"a"})
        self.assertEqual(result["per_class"]["reconnaissance_port_scan"]["fn"], 1)
        self.assertEqual(result["per_class"]["botnet_c2_beaconing"]["fp"], 1)

    def test_unknown_background_is_not_tn_or_fp(self):
        units = [{"unit_id": "unknown", "flow_ids": ["a"], "label": "unknown", "expected_classes": []}]
        result = score_units(units, [{"alert_id": "x", "flow_ids": ["a"], "subtype": "periodic_beacon"}], {"a"})
        self.assertEqual(result["binary_alert_coverage"]["tn"], 0)
        self.assertEqual(result["binary_alert_coverage"]["fp"], 0)
        self.assertEqual(result["coverage"]["unknown_units_with_alerts"], 1)

    def test_missing_denominator_is_null_not_perfect(self):
        result = metrics({"tn": 10})
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])
        self.assertGreater(result["fpr_interval_95"][1], 0)

    def test_generic_malware_does_not_validate_specific_classes(self):
        units = [{"unit_id": "a", "flow_ids": ["a"], "label": "attack", "expected_classes": ["any_attack"]}]
        result = score_units(units, [], {"a"})
        self.assertEqual(result["binary_alert_coverage"]["fn"], 1)
        self.assertEqual(result["per_class"]["dga_domain"]["fn"], 0)
        self.assertIsNone(result["per_class"]["dga_domain"]["recall"])

    def test_rejected_attack_units_remain_misses(self):
        units = [{"unit_id": "a", "flow_ids": ["a"], "label": "attack", "expected_classes": ["any_attack"]}]
        result = score_units(units, [], set())
        self.assertEqual(result["binary_alert_coverage"]["fn"], 1)
        self.assertEqual(result["coverage"]["units_with_rejected_or_unavailable_records"], 1)

    def test_overlapping_label_units_rejected_and_unlabelled_explicit(self):
        unit = {"unit_id": "a", "flow_ids": ["a"], "label": "benign", "expected_classes": []}
        with self.assertRaisesRegex(ValueError, "overlap"):
            validate_units([unit, {**unit, "unit_id": "b"}], {"a"})
        self.assertEqual(validate_units([unit], {"a", "unknown"})[-1]["label"], "unknown")

    def test_repeated_alerts_do_not_inflate_false_positives(self):
        unit = {"unit_id": "a", "flow_ids": ["a"], "label": "benign", "expected_classes": []}
        alerts = [{"alert_id": str(i), "flow_ids": ["a"], "subtype": "periodic_beacon"} for i in range(3)]
        self.assertEqual(score_units([unit], alerts, {"a"})["binary_alert_coverage"]["fp"], 1)


class CTUAndDNSSplitTests(unittest.TestCase):
    def test_ctu_adapter_preserves_label_semantics_and_missing_features(self):
        header = "StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,TotBytes,SrcBytes,Label\n"
        text = header + "\n".join(f"2011/08/18 15:39:35.000000,1,tcp,147.32.84.1,40000,198.51.100.1,80,1000,100,{label}"
                                 for label in ("flow=From-Botnet-V52-TCP-Established", "flow=From-Normal-V52", "flow=To-Botnet-V52", "flow=Background"))
        records, units, details = ctu13_records(text, 120)
        self.assertEqual([u["label"] for u in units], ["attack", "benign", "unknown", "unknown"])
        self.assertEqual(records[0]["resp_bytes"], 900)
        self.assertNotIn("conn_state", records[0])
        self.assertNotIn("orig_pkts", records[0])
        self.assertNotIn("Label", records[0])
        self.assertEqual(details["adapter"], "ctu13-argus-v1")
        with self.assertRaises(ValueError):
            ctu13_records(text, None)

    def test_dns_validation_split_family_and_duplicate_guards(self):
        first = DNSLabelledDomain("a.example", 1, "family-a", "train")
        for other in (replace(first, domain="b.example", split="validation"),
                      replace(first, domain="b.example", family="FAMILY-A", split="test"),
                      replace(first, domain="A.EXAMPLE")):
            with self.assertRaises(ValueError):
                validate_leakage_safe_split([first, other])
        with self.assertRaises(ValueError):
            DNSNgramModel.train([first, replace(first, split="test")])


if __name__ == "__main__":
    unittest.main()
