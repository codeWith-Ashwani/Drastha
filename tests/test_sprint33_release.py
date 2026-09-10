from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint33_release import validate_manifest  # noqa: E402


class Sprint33ReleaseTests(unittest.TestCase):
    def test_repository_manifest_and_checksums_are_valid(self) -> None:
        manifest = json.loads((ROOT / "data/manifests/drastha-sih-release-v2.json").read_text())
        digests = validate_manifest(ROOT, manifest)
        self.assertEqual(len(digests), 10)

    def test_changed_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "proof.json"
            evidence.write_text("{}", encoding="utf-8")
            manifest = {
                "schema_version": "drastha-sih-release-manifest-v2",
                "status": "submission_demo_ready",
                "production_ready": False,
                "evidence": [{"path": "proof.json", "sha256": "0" * 64}],
            }
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                validate_manifest(root, manifest)

    def test_parent_traversal_is_rejected(self) -> None:
        manifest = {
            "schema_version": "drastha-sih-release-manifest-v2",
            "status": "submission_demo_ready",
            "production_ready": False,
            "evidence": [{"path": "../proof.json", "sha256": "0" * 64}],
        }
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            validate_manifest(ROOT, manifest)


if __name__ == "__main__":
    unittest.main()
