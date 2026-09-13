"""Causal DNS context and encrypted tail-window evidence regressions."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.detectors.dns import DNSDetector
from aegisflow.detectors.encrypted import EncryptedSessionAnomalyDetector
from aegisflow.dns_model import DNSNgramModel
from aegisflow.ingestion.zeek_encrypted import normalize_encrypted_record
from aegisflow.models import DNSEvent
from aegisflow.passive_features import PassiveFeatureExtractor


def dns(index: int, *, response: str, source: str = "10.0.0.2", spacing: float = .5) -> DNSEvent:
    return DNSEvent(1000 + index * spacing, f"D{index}", source, "10.0.0.53",
                    f"word{index}.example", "A", response)


class _HighModel:
    payload = {}

    def predict_probability(self, _domain):
        return .9


def tls(index: int, *, rare=False, attack=False):
    timestamp = 2000 + index
    clock = timestamp - 2
    observations = []
    for packet in range(12):
        clock += (.1 if attack and packet >= 4 else .001)
        observations.append({"ts": clock,
                             "ip_bytes": 1400 if attack and packet >= 4 else 100,
                             "direction": "orig" if packet % 2 == 0 else "resp"})
    return normalize_encrypted_record({
        "ts": timestamp, "uid": f"TLS{index}", "transport": "tls",
        "id.orig_h": "10.0.0.3" if rare else "10.0.0.2",
        "id.resp_h": "198.51.100.8", "id.resp_p": 443,
        "ja3": ("rare" if attack else "rare-benign" if rare else "common"),
        "packet_observations": observations,
    })


class SIHContextHardeningTests(unittest.TestCase):
    def test_failed_research_candidate_cannot_be_loaded_for_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps({"research_status": "not_approved"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                DNSNgramModel.load(path)

    def test_failed_distinct_dns_campaign_needs_real_response_context(self):
        detector = DNSDetector()
        alerts = [alert for index in range(15)
                  for alert in detector.process(dns(index, response="NXDOMAIN"))]
        self.assertEqual([alert.subtype for alert in alerts], ["dga_like_domain"])
        evidence = {item.name: item.observed for item in alerts[0].evidence}
        self.assertGreaterEqual(evidence["distinct_queried_roots"], 10)
        self.assertEqual(evidence["nxdomain_ratio"], 1)
        for response, spacing in (("NOERROR", .5), ("NXDOMAIN", 7), ("UNKNOWN", .5)):
            with self.subTest(response=response, spacing=spacing):
                control = DNSDetector()
                self.assertFalse([alert for index in range(15)
                                  for alert in control.process(dns(index, response=response,
                                                                   spacing=spacing))])

    def test_isolated_model_positive_with_known_resolver_result_needs_corroboration(self):
        detector = DNSDetector(model=_HighModel())
        self.assertEqual(detector.process(dns(0, response="NOERROR")), [])
        self.assertEqual(detector.process(dns(1, response="NOERROR")), [])
        alerts = detector.process(dns(2, response="NOERROR"))
        self.assertEqual([item.subtype for item in alerts], ["dga_like_domain"])
        self.assertEqual(DNSDetector(model=_HighModel()).process(
            dns(0, response="UNKNOWN"))[0].subtype, "dga_like_domain")

    def test_encrypted_tail_requires_size_and_timing_not_just_rare_fingerprint(self):
        extractor = PassiveFeatureExtractor()
        detector = EncryptedSessionAnomalyDetector()
        for index in range(110):
            self.assertFalse(detector.process(extractor.enrich(tls(index))))
        for index in range(110, 114):
            benign = extractor.enrich(tls(index, rare=True))
            self.assertEqual(benign.raw["features"]["packet_size_sequence_anomaly"], 0)
            self.assertFalse(detector.process(benign))
        alerts = []
        for index in range(114, 118):
            anomalous = extractor.enrich(tls(index, rare=True, attack=True))
            self.assertEqual(anomalous.raw["feature_provenance"]["sequence_selection"],
                             "last_observed_packets")
            self.assertEqual(anomalous.raw["features"]["packet_size_sequence_anomaly"], 1)
            self.assertEqual(anomalous.raw["features"]["timing_sequence_anomaly"], 1)
            alerts.extend(detector.process(anomalous))
        self.assertEqual([item.subtype for item in alerts], ["encrypted_session_metadata_anomaly"])


if __name__ == "__main__":
    unittest.main()
