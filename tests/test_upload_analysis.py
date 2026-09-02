import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.upload_analysis import analyse_uploaded_replay


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


def record(uid, timestamp, src, dst, port, *, history="D", outbound=60, inbound=0):
    return {
        "ts": timestamp,
        "uid": uid,
        "id.orig_h": src,
        "id.orig_p": 50000,
        "id.resp_h": dst,
        "id.resp_p": port,
        "proto": "tcp",
        "history": history,
        "orig_bytes": outbound,
        "resp_bytes": inbound,
    }


class UploadAnalysisTests(unittest.TestCase):
    def test_standalone_dns_records_do_not_require_connection_fields(self):
        records = [
            {
                "ts": 1700000000 + index,
                "uid": f"dns-only-{index}",
                "id.orig_h": "10.0.0.12",
                "id.resp_h": "10.0.0.53",
                "query": f"x7q9z{index}k4m2n8p{index}.invalid",
                "qtype_name": "A",
            }
            for index in range(3)
        ]
        report = analyse_uploaded_replay("dns-only.json", json.dumps(records), _Repository())
        self.assertEqual(report["quality"]["records_accepted"], 3)
        self.assertEqual(report["telemetry"]["connection_records"], 0)
        self.assertEqual(report["telemetry"]["dns_records"], 3)
        self.assertIn("dga_like_domain", {item["subtype"] for item in report["alerts"]})

    def test_wrapper_json_iso_timestamps_and_threat_specific_routing(self):
        ports = (21, 22, 23, 25, 53, 80, 443)
        records = [
            record(f"scan-{index}", f"2026-09-01T17:01:0{index}Z", "192.0.2.10", "192.0.2.20", port)
            for index, port in enumerate(ports)
        ]
        records.append(record(
            "exfil-1", "2026-09-01T17:02:05Z", "192.0.2.90", "203.0.113.120",
            443, history="S", outbound=18_500_000, inbound=42_000,
        ))
        content = json.dumps({
            "dataset_name": "wrapped-replay",
            "records": records,
        }, indent=2)
        report = analyse_uploaded_replay("wrapped.json", content, _Repository())
        subtypes = {item["subtype"] for item in report["alerts"]}
        self.assertEqual(subtypes, {"vertical_port_scan", "outbound_volume_anomaly"})
        self.assertTrue(report["telemetry"]["supplied_labels_ignored"])
        self.assertEqual(report["quality"]["records_accepted"], 8)
        recon = next(item for item in report["alerts"] if item["subtype"] == "vertical_port_scan")
        ports_evidence = next(
            item for item in recon["evidence"] if item["name"] == "unique_destination_ports"
        )
        self.assertEqual(ports_evidence["observed"], 7)

    def test_recon_alert_survives_after_scan_expires_from_final_window(self):
        records = [
            record(
                f"scan-{index}", index, "192.0.2.10", "192.0.2.20", port
            )
            for index, port in enumerate((21, 22, 23, 25, 53, 80))
        ]
        records.append(record(
            "later-benign", 100, "192.0.2.10", "192.0.2.30", 443,
            history="S", outbound=200, inbound=500,
        ))
        report = analyse_uploaded_replay(
            "expired-scan.json", json.dumps(records), _Repository()
        )
        self.assertIn(
            "vertical_port_scan", {item["subtype"] for item in report["alerts"]}
        )

    def test_ml_evidence_routes_dns_and_tls_without_trusting_labels(self):
        records = []
        for index, domain in enumerate((
            "xqzv7m2k9p4r.example",
            "n8v2kq7z1m5t.example",
            "q9x4z7m2v8kp.example",
        )):
            item = record(
                f"dns-{index}", f"2026-09-01T17:01:0{index}Z",
                "192.0.2.60", "10.0.0.53", 53,
            )
            item.update({
                "proto": "udp", "service": "dns", "label": "attack",
                "threat_class": "untrusted-answer-key", "confidence": 1.0,
                "ml_evidence": {"query_name": domain, "record_type": "A"},
            })
            records.append(item)
        for index in range(4):
            item = record(
                f"tls-{index}", f"2026-09-01T17:01:{35 + index * 5:02d}Z",
                "192.0.2.70", "203.0.113.90", 443,
                history="S", outbound=310, inbound=920,
            )
            item.update({
                "service": "ssl",
                "ml_evidence": {
                    "tls_version": "TLSv1.3", "ja4": "t13-demo-ja4",
                    "ja4_prevalence": 0.002,
                    "packet_size_sequence_anomaly": 0.88,
                    "timing_sequence_anomaly": 0.84,
                },
            })
            records.append(item)
        report = analyse_uploaded_replay(
            "mixed.json", json.dumps({"records": records}), _Repository()
        )
        self.assertEqual(report["telemetry"]["dns_records"], 3)
        self.assertEqual(report["telemetry"]["encrypted_session_records"], 4)
        subtypes = {item["subtype"] for item in report["alerts"]}
        self.assertIn("dga_like_domain", subtypes)
        self.assertIn("encrypted_session_metadata_anomaly", subtypes)
        self.assertNotIn("untrusted-answer-key", subtypes)


if __name__ == "__main__":
    unittest.main()
