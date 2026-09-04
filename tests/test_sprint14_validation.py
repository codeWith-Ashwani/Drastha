import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from check_sustained_ingestion import LoadConfig, assess, distribution, isolated_api, resident_bytes, run, workload
from check_sensor_integration import check, checksum, main as sensor_main, probe, scan_pcap


class Sprint14ValidationTests(unittest.TestCase):
    def test_bounded_configuration_rejects_invalid_values(self):
        for kwargs in ({"rate": 0}, {"rate": True}, {"seconds": float("nan")}, {"seconds": 0},
                       {"rate": 5000, "seconds": 60}, {"seconds": 301}, {"drain_seconds": 121},
                       {"batch_records": 5000}, {"rss_budget_mib": -1}, {"latency_budget_ms": float("inf")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                LoadConfig(**kwargs)

    def test_quantiles_have_explicit_empty_denominator(self):
        self.assertEqual(distribution([]), {"count": 0, "p50": None, "p95": None, "max": None})
        self.assertEqual(distribution(range(1, 21)), {"count": 20, "p50": 10, "p95": 19, "max": 20})

    def test_workload_is_deterministic_chronological_and_has_unique_uids(self):
        records = list(workload(LoadConfig(rate=100, seconds=2)))
        self.assertEqual(records, list(workload(LoadConfig(rate=100, seconds=2))))
        self.assertEqual(len(records), 200)
        self.assertEqual(len({record["uid"] for record in records}), 200)
        self.assertTrue(all(a["ts"] < b["ts"] for a, b in zip(records, records[1:])))
        self.assertEqual(sum(r["conn_state"] == "S0" for r in records), 20)
        self.assertFalse(any("evaluation_label" in r for r in records))
        self.assertTrue(all(all(k in r for k in ("ts", "uid", "id.orig_h", "id.resp_h", "proto")) for r in records))

    def gates(self, **changes):
        args = dict(emitted=100, observed=100,
                    quality={"records_accepted": 100, "records_rejected": 0, "status": "healthy"},
                    lag=distribution([1] * 100), latency=distribution([10] * 100),
                    rss=50, disk=10, errors=[], source_matches=True)
        args.update(changes)
        return assess(LoadConfig(rate=100, seconds=1), **args)

    def test_missing_records_cannot_pass_using_observed_subset_latency(self):
        self.assertTrue(all(self.gates().values()))
        gates = self.gates(observed=99, latency=distribution([1] * 99))
        self.assertFalse(gates["all_records_api_observed"])
        self.assertFalse(gates["api_visibility_p95_within_budget"])

    def test_producer_lag_overload_and_resource_failures_remain_failures(self):
        for kwargs, gate in (({"lag": distribution([101] * 100)}, "producer_kept_schedule"),
                             ({"latency": distribution([1001] * 100)}, "api_visibility_p95_within_budget"),
                             ({"emitted": 99}, "all_offered_records_emitted"),
                             ({"rss": 513}, "rss_within_budget"), ({"disk": 513}, "disk_within_budget"),
                             ({"source_matches": False}, "source_bytes_preserved"),
                             ({"errors": ["deadline"]}, "no_runtime_errors")):
            with self.subTest(gate=gate):
                self.assertFalse(self.gates(**kwargs)[gate])

    def test_degraded_telemetry_never_passes(self):
        self.assertFalse(self.gates(quality={"records_accepted": 100, "records_rejected": 0,
                                            "status": "degraded"})["no_rejections_healthy"])

    def test_real_rss_measurement(self):
        self.assertGreater(resident_bytes(), 0)

    def test_isolated_api_restores_operator_environment(self):
        settings = {"DRASTHA_DB": "operator.db", "DRASTHA_AUTH_MODE": "required",
                    "DRASTHA_AUTH_FILE": "operator-auth.json", "DRASTHA_AUDIT_KEY_FILE": "operator.key"}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, settings):
            with isolated_api(Path(folder)) as factory:
                self.assertTrue(callable(factory))
            self.assertEqual({k: os.environ[k] for k in settings}, settings)

    def test_paced_unsigned_and_signed_actual_worker_and_api(self):
        for signed in (False, True):
            with self.subTest(signed=signed):
                # Timing gates are generous in CI; this is a correctness smoke,
                # never a capacity claim. Measured 60-second runs live separately.
                report = run(LoadConfig(rate=200, seconds=2, signed=signed,
                                        producer_lag_budget_ms=10000, latency_budget_ms=10000))
                self.assertTrue(report["passed"], (report["gates"], report["errors"]))
                self.assertFalse(report["sustained_target_demonstrated"])
                self.assertEqual(report["api_observed"], 400)
                self.assertEqual(report["quality"]["status"], "healthy")
                self.assertEqual(report["quality"]["records_rejected"], 0)
                self.assertEqual(report["final_backlog_records"], 0)
                self.assertLessEqual(report["queue_high_watermark"], 64)
                self.assertTrue(report["first_alert_observations"])
                self.assertGreaterEqual(report["first_alert_observations"][0]["latest_supporting_record_to_api_ms"], 0)

    def test_resource_stop_is_reported_not_hidden(self):
        report = run(LoadConfig(rate=20, seconds=.2, rss_budget_mib=.001))
        self.assertFalse(report["passed"])
        self.assertIn("resource budget exceeded", report["errors"])

    def test_sensor_unavailable_is_blocked_not_success(self):
        with patch("check_sensor_integration.shutil.which", return_value=None):
            result = check()
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["passed"])

    def test_sensor_probe_timeout_is_explicit(self):
        with patch("check_sensor_integration.shutil.which", return_value="wsl.exe"), \
                patch("check_sensor_integration.subprocess.run", side_effect=subprocess.TimeoutExpired("wsl", 15)):
            runner, result = probe("wsl")
        self.assertIsNone(runner)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("timed out", result["attempts"][0]["error"])

    def test_sensor_checker_actual_upload_with_stubbed_external_conversion(self):
        # Exercises the adapter/report assertions without pretending CI installed Zeek.
        class StubRunner:
            def process_pcap(self, pcap, directory):
                from types import SimpleNamespace
                directory.mkdir()
                records = [{"ts": 1000 + i / 10, "uid": f"Z{i}", "proto": "tcp", "conn_state": "S0",
                            "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
                            "id.orig_p": 40000 + i, "id.resp_p": 1000 + i} for i in range(6)]
                path = directory / "conn.log"
                path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
                return SimpleNamespace(conn_log=path)

        with patch("check_sensor_integration.probe", return_value=(StubRunner(), {"status": "test-stub"})):
            report = check()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["quality"]["records_accepted"], 6)

    def test_sensor_execution_failure_is_not_downgraded_to_skip(self):
        from unittest.mock import Mock
        runner = Mock()
        runner.process_pcap.side_effect = RuntimeError("conversion failed")
        with patch("check_sensor_integration.probe", return_value=(runner, {"status": "test-stub"})):
            report = check()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["passed"])

    def test_sensor_blocked_exit_code(self):
        import contextlib
        import io
        with patch("sys.argv", ["check_sensor_integration.py"]), \
                patch("check_sensor_integration.check", return_value={"passed": False, "status": "blocked"}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sensor_main(), 2)

    def test_synthetic_sensor_capture_contains_only_six_valid_syn_frames(self):
        raw = scan_pcap()
        self.assertEqual(raw, scan_pcap())
        self.assertEqual(struct.unpack_from("<I", raw)[0], 0xa1b2c3d4)
        offset, ports = 24, []
        while offset < len(raw):
            _, _, captured, original = struct.unpack_from("<IIII", raw, offset)
            self.assertEqual(captured, original)
            packet = raw[offset + 16:offset + 16 + captured]
            ip, tcp = packet[14:34], packet[34:]
            self.assertEqual(checksum(ip), 0)
            self.assertEqual(checksum(ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp)) + tcp), 0)
            self.assertEqual(tcp[13], 2)
            self.assertEqual(len(tcp), 20)
            ports.append(struct.unpack_from("!H", tcp, 2)[0])
            offset += 16 + captured
        self.assertEqual(ports, list(range(1000, 1006)))


if __name__ == "__main__":
    unittest.main()
