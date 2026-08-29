import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.detectors.recon import ReconConfig, ReconDetector
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl
from aegisflow.pipeline import run_pipeline


class PipelineTests(unittest.TestCase):
    def test_example_replay_produces_one_vertical_scan(self):
        root = Path(__file__).resolve().parents[1]
        detector = ReconDetector(ReconConfig(
            window_seconds=10, unique_port_threshold=5, unique_host_threshold=5,
        ))
        alerts = list(run_pipeline(
            read_conn_jsonl(root / "examples" / "zeek_conn_scan.jsonl"),
            [detector],
        ))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].subtype, "vertical_port_scan")


if __name__ == "__main__":
    unittest.main()

