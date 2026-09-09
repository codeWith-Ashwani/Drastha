from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE  # noqa: E402
from aegisflow.deployment_config import load_deployment_config  # noqa: E402
from aegisflow.models import NetworkEvent  # noqa: E402
from check_sprint23_deployment import audit  # noqa: E402


class Sprint23DeploymentTests(unittest.TestCase):
    def test_read_only_release_audit_passes_all_gates(self):
        report = audit(ROOT)
        self.assertTrue(report["passed"], report["gates"])
        self.assertFalse(report["production_ready"])
        self.assertTrue(all(report["gates"].values()))

    def test_checked_in_contract_pins_boundaries_policy_and_confidence_semantics(self):
        settings = load_deployment_config(ROOT / "config" / "deployment_profile.json")
        self.assertEqual("staged-enclave-lab-v1", settings.deployment_id)
        self.assertEqual(
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
            settings.internal_cidrs,
        )
        self.assertEqual("heuristic_evidence_score", settings.confidence_semantics)
        self.assertEqual("not_probability_calibrated", settings.confidence_calibration_status)
        self.assertEqual(64, len(settings.context_policy_sha256))

    def test_policy_tamper_and_unsafe_or_ambiguous_contracts_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            body = {
                "schema_version": "drastha-deployment-v1",
                "deployment_id": "test-enclave-v1",
                "internal_cidrs": ["10.0.0.0/8"],
                "context_policy": {"path": "policy.json", "sha256": sha256(policy.read_bytes()).hexdigest()},
                "confidence": {"semantics": "heuristic_evidence_score", "probability_calibrated": False,
                               "calibration_status": "not_probability_calibrated"},
                "dns_model": None,
                "passive_constraints": {"read_only_ingest": True, "no_return_path": True,
                                        "payload_decryption": False, "active_mitigation": False},
            }
            config = root / "deployment.json"
            config.write_text(json.dumps(body), encoding="utf-8")
            self.assertEqual("test-enclave-v1", load_deployment_config(config).deployment_id)
            policy.write_text('{"changed":true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_deployment_config(config)
            policy.write_text("{}", encoding="utf-8")
            for change, message in (
                ({"internal_cidrs": ["10.0.0.0/8", "10.1.0.0/16"]}, "overlapping"),
                ({"confidence": {"semantics": "probability", "probability_calibrated": True,
                                 "calibration_status": "calibrated"}}, "semantics"),
                ({"passive_constraints": {"read_only_ingest": False}}, "passive"),
            ):
                config.write_text(json.dumps({**body, **change}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    load_deployment_config(config)

    def test_runtime_uses_one_boundary_authority_and_exposes_score_semantics(self):
        config = ROOT / "config" / "deployment_profile.json"
        with patch.dict(os.environ, {"DRASTHA_DEPLOYMENT_CONFIG": str(config)}, clear=False):
            os.environ.pop("DRASTHA_INTERNAL_NETWORKS", None)
            session = AnalysisSession.from_root(ROOT, DEPLOYMENT_BASELINE)
            self.assertEqual("deployment:staged-enclave-lab-v1", session.profile.name)
            self.assertEqual("outbound", session.network_scope.direction("10.1.2.3", "203.0.113.8"))
            provenance = session.provenance()
            self.assertFalse(provenance["confidence_is_probability"])
            self.assertEqual("not_probability_calibrated", provenance["confidence_calibration_status"])
            self.assertIsNone(session.dns_model)
        with patch.dict(os.environ, {
            "DRASTHA_DEPLOYMENT_CONFIG": str(config),
            "DRASTHA_INTERNAL_NETWORKS": "10.0.0.0/8",
        }, clear=False):
            with self.assertRaisesRegex(ValueError, "two authorities"):
                AnalysisSession.from_root(ROOT, DEPLOYMENT_BASELINE)
        with patch.dict(os.environ, {
            "DRASTHA_DEPLOYMENT_CONFIG": str(config),
            "DRASTHA_DNS_MODEL": "unapproved.json",
        }, clear=False):
            os.environ.pop("DRASTHA_INTERNAL_NETWORKS", None)
            with self.assertRaisesRegex(ValueError, "no approved DNS model"):
                AnalysisSession.from_root(ROOT, DEPLOYMENT_BASELINE)

    def test_alert_schema_never_labels_detector_confidence_as_probability(self):
        session = AnalysisSession(replace(
            DEPLOYMENT_BASELINE,
            enabled=("recon",),
            recon=replace(DEPLOYMENT_BASELINE.recon, unique_port_threshold=2),
        ))
        session.process(NetworkEvent(1, "a", "10.0.0.1", "10.0.0.2", 50000, 80, "tcp"))
        alert = session.process(NetworkEvent(2, "b", "10.0.0.1", "10.0.0.2", 50001, 81, "tcp"))[0].to_dict()
        self.assertEqual("heuristic_evidence_score", alert["confidence_semantics"])
        self.assertEqual("not_probability_calibrated", alert["confidence_calibration_status"])
        self.assertFalse(alert["confidence_is_probability"])


if __name__ == "__main__":
    unittest.main()
