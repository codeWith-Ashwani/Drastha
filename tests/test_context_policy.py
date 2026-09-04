import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.context_policy import load_context_policy
from aegisflow.models import NetworkEvent


class ContextPolicyTests(unittest.TestCase):
    def test_exact_endpoint_context_is_loaded_and_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config" / "context_policy.json").write_text(json.dumps({
                "trusted_periodic_endpoints": [{
                    "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                    "dst_port": 443, "protocol": "tcp", "service": "https",
                    "purpose": "health check",
                }],
            }), encoding="utf-8")
            policy = load_context_policy(root)
        event = NetworkEvent(
            timestamp=1, flow_id="flow", src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=50000, dst_port=443, protocol="tcp", raw={"service": "https"},
        )
        self.assertTrue(policy.trusted_periodic_endpoints[0].matches(event))

    def test_missing_policy_is_safe_and_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = load_context_policy(directory)
        self.assertEqual(policy.trusted_periodic_endpoints, ())
        self.assertEqual(policy.approved_bulk_transfer_endpoints, ())
        self.assertEqual(policy.authorized_scanner_sources, ())

    def test_authorized_scanners_are_operator_policy_not_record_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/context_policy.json").write_text(json.dumps({
                "authorized_scanner_sources": ["192.0.2.50"],
            }))
            policy = load_context_policy(root)
        self.assertEqual(policy.authorized_scanner_sources, ("192.0.2.50",))


if __name__ == "__main__":
    unittest.main()
