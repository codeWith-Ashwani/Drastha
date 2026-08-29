import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.ingestion.zeek_runner import WSLZeekRunner, ZeekRunner, ZeekUnavailableError


class ZeekRunnerTests(unittest.TestCase):
    def test_unavailable_binary_has_actionable_error(self):
        with self.assertRaisesRegex(ZeekUnavailableError, "Install Zeek"):
            ZeekRunner("definitely-not-a-real-zeek-binary").check_available()

    def test_process_pcap_builds_expected_zeek_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "zeek.exe"
            executable.write_bytes(b"placeholder")
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"pcap-placeholder")
            output = root / "zeek-output"

            def fake_run(command, cwd, text, capture_output, check):
                self.assertIn("-r", command)
                self.assertIn(str(pcap.resolve()), command)
                self.assertIn("LogAscii::use_json=T", command)
                Path(cwd, "conn.log").write_text("", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            with patch("aegisflow.ingestion.zeek_runner.subprocess.run", side_effect=fake_run):
                result = ZeekRunner(str(executable)).process_pcap(pcap, output)
            self.assertEqual(result.conn_log, output.resolve() / "conn.log")

    def test_wsl_availability_uses_linux_zeek_path(self):
        completed = subprocess.CompletedProcess([], 0, "zeek version 8.0.10", "")
        with patch("aegisflow.ingestion.zeek_runner.subprocess.run", return_value=completed) as run:
            resolved = WSLZeekRunner(distribution="Ubuntu").check_available()
        self.assertEqual(resolved, "WSL:Ubuntu:/opt/zeek/bin/zeek")
        self.assertEqual(
            run.call_args.args[0],
            ["wsl.exe", "--distribution", "Ubuntu", "--", "/opt/zeek/bin/zeek", "--version"],
        )

    def test_wsl_process_translates_paths_and_runs_zeek(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"pcap-placeholder")
            output = root / "zeek-output"
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "zeek version", "")
                (output / "conn.log").write_text("", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("aegisflow.ingestion.zeek_runner.subprocess.run", side_effect=fake_run):
                result = WSLZeekRunner().process_pcap(pcap, output)

            self.assertEqual(result.conn_log, output.resolve() / "conn.log")
            self.assertIn("--cd", calls[-1])
            self.assertTrue(any(argument.startswith("/mnt/") for argument in calls[-1]))

    def test_wsl_unc_path_maps_back_to_linux_path(self):
        runner = WSLZeekRunner()
        translated = runner._wsl_path(
            Path(r"\\wsl.localhost\Ubuntu\home\analyst\capture.pcap")
        )
        self.assertEqual(translated, "/home/analyst/capture.pcap")


if __name__ == "__main__":
    unittest.main()
