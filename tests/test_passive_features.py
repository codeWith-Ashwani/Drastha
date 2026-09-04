import json
import os
from dataclasses import replace
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
from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE, UPLOAD_DEMO
from aegisflow.detectors.ddos import DDoSConfig, DDoSDetector
from aegisflow.ingestion.zeek_encrypted import normalize_encrypted_record
from aegisflow.ingestion.zeek_jsonl import _timestamp, ZeekRecordError
from aegisflow.models import NetworkEvent
from aegisflow.network_context import NetworkScope
from aegisflow.passive_features import PassiveFeatureExtractor, PassiveFeatureConfig
from aegisflow.streaming_demo import stream_replay


def metadata(index, *, attack=False):
    timestamp = 1000 + index
    gap, size = (.1, 1400) if attack else (.001, 100)
    return {"ts": timestamp, "uid": f"T{index}", "transport": "tls",
            "id.orig_h": "10.0.0.9" if attack else "10.0.0.2", "id.resp_h": "198.51.100.8",
            "id.resp_p": 443, "ja3": "rare" if attack else "common",
            "packet_observations": [{"ts": timestamp - (3-i)*gap, "ip_bytes": size,
                                      "direction": "orig" if i % 2 == 0 else "resp"} for i in range(4)]}


class PassiveFeaturesTests(unittest.TestCase):
    def test_causal_derived_features_and_normal_history(self):
        extractor = PassiveFeatureExtractor()
        for index in range(400):
            result = extractor.enrich(normalize_encrypted_record(metadata(index)))
        self.assertEqual(result.raw["features"]["fingerprint_prevalence"], 1)
        self.assertEqual(result.raw["features"]["packet_size_sequence_anomaly"], 0)
        rare = extractor.enrich(normalize_encrypted_record(metadata(400, attack=True)))
        self.assertEqual(rare.raw["feature_provenance"]["baseline_sessions"], 400)
        self.assertEqual(rare.raw["features"], {"fingerprint_prevalence": 0, "packet_size_sequence_anomaly": 1,
                                              "timing_sequence_anomaly": 1})
        next_rare = extractor.enrich(normalize_encrypted_record(metadata(401, attack=True)))
        self.assertEqual(next_rare.raw["feature_provenance"]["baseline_sessions"], 400)
        self.assertEqual(next_rare.raw["features"]["fingerprint_prevalence"], 0)
        self.assertEqual(extractor.summary()["counts"]["anomalous_sessions_excluded_from_baseline"], 2)

    def test_missing_sequences_and_warmup_are_not_benign_scores(self):
        extractor = PassiveFeatureExtractor()
        record = metadata(0)
        record.pop("packet_observations")
        result = extractor.enrich(normalize_encrypted_record(record), allow_supplied=True)
        self.assertEqual(result.raw["features"], {})
        self.assertEqual(result.raw["feature_provenance"]["status"], "insufficient_evidence")
        warm = extractor.enrich(normalize_encrypted_record(metadata(1)))
        self.assertIn("sequence_baseline_warmup", warm.raw["feature_provenance"]["reasons"])

    def test_supplied_features_cannot_bypass_derived_mode(self):
        record = metadata(0)
        record.pop("packet_observations")
        record["ml_evidence"] = {"ja4_prevalence": 0, "packet_size_sequence_anomaly": 1, "timing_sequence_anomaly": 1}
        event = normalize_encrypted_record(record)
        strict = PassiveFeatureExtractor().enrich(event)
        self.assertEqual(strict.raw["features"], {})
        compatible = PassiveFeatureExtractor().enrich(event, allow_supplied=True)
        self.assertEqual(compatible.raw["feature_provenance"]["status"], "supplied_compatibility")
        self.assertNotIn("feature_provenance", event.raw)

    def test_invalid_sequences_do_not_fallback_to_supplied_scores(self):
        variants = [None, [], [{"ts": 1001, "ip_bytes": 100, "direction": "orig"}]*4,
                    [{"ts": 999, "ip_bytes": float("nan"), "direction": "orig"}]*4,
                    [{"ts": 999, "ip_bytes": 100, "direction": "bad"}]*4,
                    [{"ts": 999, "ip_bytes": 100, "direction": "orig"}]*129]
        for sequence in variants:
            with self.subTest(sequence=str(sequence)[:40]):
                record = metadata(0)
                record["packet_observations"] = sequence
                record["features"] = {"ja4_prevalence": 0, "packet_size_sequence_anomaly": 1, "timing_sequence_anomaly": 1}
                event = PassiveFeatureExtractor().enrich(normalize_encrypted_record(record), allow_supplied=True)
                self.assertEqual(event.raw["feature_provenance"]["status"], "insufficient_evidence")

    def test_invalid_supplied_features_are_visible_in_coverage(self):
        record = metadata(0)
        record.pop("packet_observations")
        record["features"] = {"ja4_prevalence": 0, "packet_size_sequence_anomaly": "NaN", "timing_sequence_anomaly": 1}
        result = PassiveFeatureExtractor().enrich(normalize_encrypted_record(record), allow_supplied=True)
        self.assertEqual(result.raw["feature_provenance"]["status"], "insufficient_evidence")
        self.assertIn("supplied_features_invalid", result.raw["feature_provenance"]["reasons"])

    def test_duplicate_sessions_do_not_inflate_baselines(self):
        extractor = PassiveFeatureExtractor()
        event = normalize_encrypted_record(metadata(0))
        extractor.enrich(event)
        again = extractor.enrich(event)
        self.assertIn("duplicate_session", again.raw["feature_provenance"]["reasons"])
        next_event = extractor.enrich(normalize_encrypted_record(metadata(1)))
        self.assertEqual(next_event.raw["feature_provenance"]["baseline_sessions"], 1)

    def test_history_expiry_and_cohort_eviction(self):
        extractor = PassiveFeatureExtractor(PassiveFeatureConfig(maximum_cohorts=1))
        extractor.enrich(normalize_encrypted_record(metadata(0)))
        event = extractor.enrich(normalize_encrypted_record(metadata(4000)))
        self.assertEqual(event.raw["feature_provenance"]["baseline_sessions"], 0)
        record = metadata(4001)
        record["sensor_id"] = "other"
        extractor.enrich(normalize_encrypted_record(record))
        self.assertEqual(extractor.summary()["counts"]["cohorts_evicted"], 1)

    def test_fingerprint_families_have_separate_cohorts(self):
        extractor = PassiveFeatureExtractor()
        extractor.enrich(normalize_encrypted_record(metadata(0)))
        record = metadata(1)
        record["ja4"] = record.pop("ja3")
        event = extractor.enrich(normalize_encrypted_record(record))
        self.assertEqual(event.raw["feature_provenance"]["baseline_sessions"], 0)
        self.assertEqual(extractor.summary()["active_cohorts"], 2)

    def test_dns_context_is_prior_same_client_and_bounded(self):
        from aegisflow.passive_context import PassiveDNSContext
        from aegisflow.models import DNSEvent
        context = PassiveDNSContext(maximum_records=2)
        dns = DNSEvent(1000, "D", "10.0.0.1", "10.0.0.53", "example.test", "A", "NOERROR", ("198.51.100.1",))
        event = NetworkEvent(1001, "C", "10.0.0.1", "198.51.100.1", 50000, 443, "tcp")
        context.observe(dns)
        self.assertTrue(context.evidence_for(event))
        self.assertEqual(context.evidence_for(replace(event, timestamp=999)), ())
        self.assertEqual(context.evidence_for(replace(event, src_ip="10.0.0.2")), ())
        self.assertEqual(context.evidence_for(replace(event, timestamp=1061)), ())
        for i in range(4):
            context.observe(replace(dns, timestamp=1070+i, flow_id=str(i)))
        self.assertEqual(len(context.history), 2)

    def test_http_upload_stream_and_persisted_derived_evidence(self):
        records = [metadata(i, attack=i >= 400) for i in range(404)]
        content = "\n".join(map(json.dumps, records))
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                "DRASTHA_ROOT": str(ROOT), "DRASTHA_ANALYSIS_PROFILE": "deployment-baseline",
                "DRASTHA_INTERNAL_NETWORKS": "10.0.0.0/8"}):
            repository = IncidentRepository(Path(folder) / "test.db")
            response = TestClient(create_app(repository)).post("/api/replays/analyse", json={"filename": "metadata.jsonl", "content": content})
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["quality"]["records_accepted"], 404)
            self.assertEqual(result["quality"]["status"], "healthy")
            self.assertEqual(len(result["alerts"]), 1)
            self.assertEqual(result["alerts"][0]["subtype"], "encrypted_session_metadata_anomaly")
            evidence = {item["name"]: item["observed"] for item in result["alerts"][0]["evidence"]}
            self.assertEqual(evidence["feature_origin"], "derived")
            self.assertEqual(evidence["baseline_session_count"], 400)
            self.assertEqual(result["feature_coverage"]["counts"]["derived"], 304)
            self.assertEqual(repository.get_analysis_run(result["run_id"])["feature_coverage"], result["feature_coverage"])
            streamed = [json.loads(item.removeprefix("data: ")) for item in
                        stream_replay(ROOT, repository, "metadata.jsonl", content, profile=DEPLOYMENT_BASELINE)][-1]
            self.assertEqual([finding["alert"] for finding in streamed["findings"]], result["alerts"])
            self.assertEqual(streamed["feature_coverage"], result["feature_coverage"])

    def test_missing_fingerprint_explicit_tls_remains_metadata(self):
        from aegisflow.ingestion.passive_replay import prepare_replay
        record = metadata(0)
        record.pop("ja3")
        prepared = prepare_replay(json.dumps(record))
        self.assertEqual(len(prepared.encrypted_events), 1)
        result = PassiveFeatureExtractor().enrich(prepared.encrypted_events[0])
        self.assertIn("fingerprint_missing", result.raw["feature_provenance"]["reasons"])

    def test_nonfinite_timestamps_rejected(self):
        for value in (float("nan"), float("inf"), "-Infinity", "NaN"):
            with self.subTest(value=value), self.assertRaises(ZeekRecordError) as error:
                _timestamp({"ts": value})
            self.assertEqual(error.exception.category, "invalid_timestamp")


class NetworkContextTests(unittest.TestCase):
    def test_boundary_direction_and_ipv6(self):
        scope = NetworkScope(("10.0.0.0/8", "2001:db8:1::/48"))
        for src, dst, expected in (("10.1.1.1", "198.51.100.1", "outbound"),
                                   ("198.51.100.1", "10.1.1.1", "inbound"),
                                   ("10.1.1.1", "10.2.1.1", "internal"),
                                   ("198.51.100.1", "203.0.113.1", "external"),
                                   ("2001:db8:1::1", "2001:db8:2::1", "outbound")):
            self.assertEqual(scope.direction(src, dst), expected)
        self.assertEqual(NetworkScope().direction("10.1.1.1", "198.51.100.1"), "unknown")
        with self.assertRaises(ValueError):
            NetworkScope(("not-a-cidr",))

    def test_inbound_request_can_exfiltrate_internal_response_bytes(self):
        event = NetworkEvent(1000, "F", "198.51.100.1", "10.0.0.2", 50000, 443, "tcp",
                             outbound_bytes=100, inbound_bytes=20_000_000)
        profile = replace(DEPLOYMENT_BASELINE, enabled=("exfiltration",), internal_cidrs=("10.0.0.0/8",))
        session = AnalysisSession(profile)
        alerts = session.process(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].src_ip, alerts[0].dst_ip), ("10.0.0.2", "198.51.100.1"))
        self.assertEqual(event.outbound_bytes, 100)
        download = replace(event, outbound_bytes=20_000_000, inbound_bytes=100)
        self.assertEqual(AnalysisSession(profile).process(download), [])
        self.assertEqual(AnalysisSession(replace(profile, internal_cidrs=())).process(event), [])
        internal = replace(event, src_ip="10.0.0.3")
        self.assertEqual(AnalysisSession(profile).process(internal), [])

    def test_udp_response_recipient_grouping_and_service_requirement(self):
        def replay(port, sent=100):
            detector = DDoSDetector(DDoSConfig(require_reflection_service_context=True))
            return [alert for i in range(4) for alert in detector.process(NetworkEvent(
                1000 + i, f"U{i}", "10.0.0.7", f"198.51.100.{i+1}", 50000+i, port, "udp",
                outbound_bytes=sent, inbound_bytes=5000))]
        alerts = replay(53)
        self.assertEqual([item.subtype for item in alerts], ["udp_reflection_amplification"])
        self.assertEqual(alerts[0].dst_ip, "10.0.0.7")
        self.assertEqual(replay(44444), [])
        self.assertEqual(replay(53, 0), [])

    def test_syn_rate_comes_from_records_not_supplied_score(self):
        detector = DDoSDetector(DDoSConfig(syn_attempt_threshold=2))
        alerts = [alert for i in range(2) for alert in detector.process(NetworkEvent(
            1000+i, f"S{i}", "10.0.0.1", "198.51.100.1", 50000, 443, "tcp", connection_state="S0",
            raw={"ml_evidence": {"syn_rate_per_sec": 999999}}))]
        rate = next(item.observed for item in alerts[0].evidence if item.name == "connection_attempt_rate_per_second")
        self.assertEqual(rate, 2)


if __name__ == "__main__":
    unittest.main()
