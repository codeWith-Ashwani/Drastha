from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from aegisflow.cli import main
from aegisflow.demo import available_demo_port, require_demo_port
from test_api_store import ALERT, INCIDENT


class DemoStartupTests(unittest.TestCase):
    def _demo_root(self, root: Path) -> Path:
        output = root / "output"
        (output / "models").mkdir(parents=True)
        (root / "web" / "dist").mkdir(parents=True)
        (output / "models" / "dns_dga_demo.json").write_text("{}\n", encoding="utf-8")
        (output / "sprint4_incidents.jsonl").write_text(json.dumps(INCIDENT) + "\n", encoding="utf-8")
        (output / "sprint3_c2_alerts.jsonl").write_text(json.dumps(ALERT) + "\n", encoding="utf-8")
        (output / "sprint4_exfil_alerts.jsonl").write_text(json.dumps(ALERT) + "\n", encoding="utf-8")
        (output / "sprint4_feedback.json").write_text("{}\n", encoding="utf-8")
        (root / "web" / "dist" / "index.html").write_text("<html></html>\n", encoding="utf-8")
        return output

    def test_available_loopback_port_passes_without_network_contact(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.assertEqual(port, available_demo_port("127.0.0.1", port, attempts=0))
        require_demo_port("localhost", port)

    def test_non_loopback_demo_bind_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "only supports loopback"):
            require_demo_port("0.0.0.0", 8000)

    def test_occupied_port_fails_before_fresh_database_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = self._demo_root(root)
            database = output / "protected-demo.db"
            database.write_bytes(b"must remain unchanged")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                port = listener.getsockname()[1]
                errors = StringIO()
                with redirect_stderr(errors):
                    result = main([
                        "demo-serve", "--root", str(root), "--database", str(database),
                        "--host", "127.0.0.1", "--port", str(port), "--fresh",
                    ])
            self.assertEqual(2, result)
            self.assertEqual(b"must remain unchanged", database.read_bytes())
            message = errors.getvalue()
            self.assertIn("already in use", message)
            self.assertIn("demo data was not reset", message)
            self.assertIn("Get-NetTCPConnection", message)

    def test_server_receives_prebound_socket_and_starting_wording(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._demo_root(root)
            captured: dict = {}

            class FakeServer:
                def __init__(self, config):
                    captured["config"] = config

                def run(self, *, sockets):
                    captured["socket"] = sockets[0]
                    captured["bound"] = sockets[0].getsockname()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            errors = StringIO()
            with patch.dict(os.environ, {"DRASTHA_DB": "previous-database"}, clear=False):
                previous_root = os.environ.pop("DRASTHA_ROOT", None)
                previous_web = os.environ.pop("DRASTHA_WEB", None)
                try:
                    with patch("uvicorn.Config", return_value="configuration"), patch("uvicorn.Server", FakeServer):
                        with redirect_stderr(errors):
                            result = main([
                                "demo-serve", "--root", str(root), "--skip-prepare",
                                "--host", "127.0.0.1", "--port", str(port),
                            ])
                    self.assertEqual("previous-database", os.environ["DRASTHA_DB"])
                    self.assertNotIn("DRASTHA_ROOT", os.environ)
                    self.assertNotIn("DRASTHA_WEB", os.environ)
                finally:
                    if previous_root is not None:
                        os.environ["DRASTHA_ROOT"] = previous_root
                    if previous_web is not None:
                        os.environ["DRASTHA_WEB"] = previous_web
            self.assertEqual(0, result)
            self.assertEqual(("127.0.0.1", port), captured["bound"])
            self.assertEqual(-1, captured["socket"].fileno())
            self.assertIn("Starting Drastha demo", errors.getvalue())
            self.assertNotIn("demo ready", errors.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
