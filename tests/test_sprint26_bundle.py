from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint26_bundle import build_bundle, verify_bundle  # noqa: E402


class Sprint26BundleTests(unittest.TestCase):
    def test_same_inputs_produce_byte_identical_verified_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            first, second = root / "first.zip", root / "second.zip"
            members = ["src/app.py"]
            one = build_bundle(root, first, members=members, source_revision="a" * 40)
            two = build_bundle(root, second, members=members, source_revision="a" * 40)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(one["sha256"], two["sha256"])
            self.assertEqual(1, one["member_count"])

    def test_changed_member_is_rejected_by_embedded_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.txt").write_text("original", encoding="utf-8")
            original, changed = root / "original.zip", root / "changed.zip"
            build_bundle(root, original, members=["safe.txt"], source_revision="b" * 40)
            with zipfile.ZipFile(original) as source, zipfile.ZipFile(changed, "w") as target:
                for info in source.infolist():
                    payload = b"changed" if info.filename == "safe.txt" else source.read(info.filename)
                    target.writestr(info, payload)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_bundle(changed)

    def test_sensitive_local_artifacts_cannot_enter_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "audit.key").write_text("secret", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot enter bundle"):
                build_bundle(root, root / "bad.zip", members=["audit.key"], source_revision="c" * 40)


if __name__ == "__main__":
    unittest.main()
