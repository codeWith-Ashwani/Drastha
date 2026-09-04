import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.dns import DNSConfig, DNSDetector
from aegisflow.models import DNSEvent


class _HighRiskModel:
    def predict_probability(self, domain):
        return 0.97


def event(index, query, source="10.0.0.10"):
    return DNSEvent(
        timestamp=1000.0 + index,
        flow_id=f"dns-{index}",
        src_ip=source,
        dst_ip="10.0.0.53",
        query=query,
        query_type="TXT",
        response_code="NOERROR",
    )


class DNSDetectorTests(unittest.TestCase):
    def test_dga_alert_is_distinct_and_explainable(self):
        detector = DNSDetector(DNSConfig(dga_probability_threshold=0.9), model=_HighRiskModel())
        alerts = detector.process(event(1, "x8q2m9z7.biz"))
        self.assertEqual(alerts[0].subtype, "dga_like_domain")
        self.assertEqual(alerts[0].threat_type, "dns_threat")
        self.assertTrue(any(item.name == "model_probability" for item in alerts[0].evidence))

    def test_dns_tunnel_window_alert(self):
        config = DNSConfig(
            window_seconds=60,
            tunnel_query_threshold=5,
            tunnel_unique_subdomain_threshold=5,
            tunnel_label_length_threshold=10,
            tunnel_entropy_threshold=3.0,
        )
        detector = DNSDetector(config)
        alerts = []
        for index in range(5):
            alerts.extend(detector.process(event(index, f"a{index}f8c2e9b7d4.tunnel.test")))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "dns_tunnelling")

    def test_hosted_service_example_does_not_cross_window_threshold(self):
        detector = DNSDetector(DNSConfig(tunnel_query_threshold=5, tunnel_unique_subdomain_threshold=5))
        domains = ["cdn.jsdelivr.net", "assets.adobedtm.com", "githubusercontent.com"]
        alerts = []
        for index, domain in enumerate(domains):
            alerts.extend(detector.process(event(index, domain)))
        self.assertEqual(alerts, [])

    def test_allowlist_suppresses_domain(self):
        detector = DNSDetector(
            DNSConfig(dga_probability_threshold=0.9),
            model=_HighRiskModel(),
            allowlisted_base_domains={"example.com"},
        )
        self.assertEqual(detector.process(event(1, "tracking.example.com")), [])

    def test_multiple_digit_heavy_random_domains_trigger_lexical_fallback(self):
        detector = DNSDetector(DNSConfig(dga_probability_threshold=0.9))
        alerts = []
        for index, domain in enumerate((
            "xqzv7m2k9p4r.example",
            "n8v2kq7z1m5t.example",
            "q9x4z7m2v8kp.example",
        )):
            alerts.extend(detector.process(event(index, domain)))
        self.assertEqual([item.subtype for item in alerts], ["dga_like_domain"])

    def test_repeated_long_high_entropy_txt_queries_trigger_strong_tunnel_path(self):
        detector = DNSDetector(DNSConfig())
        alerts = []
        query = "a8f3c91d72e4b6f0" * 4 + ".tunnel.example"
        for index in range(4):
            alerts.extend(detector.process(event(index * 3, query)))
        self.assertEqual([item.subtype for item in alerts], ["dns_tunnelling"])
        evidence = {item.name: item for item in alerts[0].evidence}
        self.assertEqual(evidence["queries_to_base_domain"].comparison, ">= 4")
        self.assertEqual(evidence["unique_subdomain_labels"].comparison,
                         "supporting feature for encoded TXT path")
        self.assertEqual(evidence["txt_query_ratio"].comparison, ">= 0.75")


if __name__ == "__main__":
    unittest.main()
