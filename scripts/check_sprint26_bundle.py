"""Build, verify and rehearse a deterministic SIH demo source bundle."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "drastha-demo-bundle-v1"
MANIFEST_NAME = "BUNDLE-MANIFEST.json"
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
FORBIDDEN_PARTS = {".git", ".venv", "node_modules", "__pycache__"}
FORBIDDEN_NAMES = {".env", ".env.local", "bootstrap-tokens.json"}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".key", ".pem", ".pcap", ".pcapng"}


def _run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def _forbidden(relative: str) -> bool:
    path = PurePosixPath(relative)
    return (
        any(part in FORBIDDEN_PARTS for part in path.parts)
        or path.name.lower() in FORBIDDEN_NAMES
        or path.suffix.lower() in FORBIDDEN_SUFFIXES
    )


def release_members(root: Path) -> list[str]:
    """Return committed files plus the locally built dashboard assets."""
    tracked = _run_git(root, "ls-files", "-z").split("\0")
    members = {item.replace("\\", "/") for item in tracked if item}
    dist = root / "web" / "dist"
    if not (dist / "index.html").is_file():
        raise ValueError("web/dist is missing; run the frontend production build first")
    members.update(
        path.relative_to(root).as_posix() for path in dist.rglob("*") if path.is_file()
    )
    return sorted(members)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def build_bundle(
    root: Path,
    output: Path,
    *,
    members: list[str] | None = None,
    source_revision: str | None = None,
) -> dict:
    root, output = root.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"Bundle output already exists: {output}")
    selected = sorted(members if members is not None else release_members(root))
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("Bundle member inventory must be nonempty and unique")
    records: list[dict] = []
    payloads: dict[str, bytes] = {}
    for relative in selected:
        normalized = PurePosixPath(relative).as_posix()
        if normalized != relative or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
            raise ValueError(f"Unsafe bundle path: {relative}")
        if _forbidden(relative):
            raise ValueError(f"Sensitive or generated local file cannot enter bundle: {relative}")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError(f"Bundle path escapes source root: {relative}") from error
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Bundle member must be a regular file: {relative}")
        raw = path.read_bytes()
        payloads[relative] = raw
        records.append({"path": relative, "bytes": len(raw), "sha256": sha256(raw).hexdigest()})
    revision = source_revision or _run_git(root, "rev-parse", "HEAD")
    manifest = {
        "schema_version": SCHEMA,
        "source_revision": revision,
        "member_count": len(records),
        "files": records,
        "frontend_prebuilt": True,
        "dependencies_included": False,
        "scope": "prepared-host offline SIH demo source bundle",
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr(_zip_info(MANIFEST_NAME), manifest_raw, compresslevel=9)
            for relative in selected:
                archive.writestr(_zip_info(relative), payloads[relative], compresslevel=9)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return verify_bundle(output)


def verify_bundle(path: Path) -> dict:
    path = path.resolve()
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or names.count(MANIFEST_NAME) != 1:
            raise ValueError("Bundle members must be unique with one manifest")
        for info in infos:
            member = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if member.is_absolute() or ".." in member.parts or info.flag_bits & 0x1:
                raise ValueError(f"Unsafe or encrypted bundle member: {info.filename}")
            if stat.S_ISLNK(mode):
                raise ValueError(f"Bundle symlink is not allowed: {info.filename}")
            if info.filename != MANIFEST_NAME and _forbidden(info.filename):
                raise ValueError(f"Forbidden bundle member: {info.filename}")
        manifest = json.loads(archive.read(MANIFEST_NAME))
        if manifest.get("schema_version") != SCHEMA:
            raise ValueError("Unsupported bundle manifest schema")
        expected = {item["path"]: item for item in manifest.get("files", [])}
        actual = set(names) - {MANIFEST_NAME}
        if set(expected) != actual or manifest.get("member_count") != len(actual):
            raise ValueError("Bundle manifest inventory does not match archive")
        for name, descriptor in expected.items():
            raw = archive.read(name)
            if len(raw) != descriptor["bytes"] or sha256(raw).hexdigest() != descriptor["sha256"]:
                raise ValueError(f"Bundle member checksum mismatch: {name}")
    raw = path.read_bytes()
    return {
        "passed": True,
        "path": str(path),
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "source_revision": manifest["source_revision"],
        "member_count": manifest["member_count"],
        "frontend_prebuilt": manifest["frontend_prebuilt"],
        "dependencies_included": manifest["dependencies_included"],
    }


def _extract_verified(bundle: Path, destination: Path) -> None:
    verify_bundle(bundle)
    with zipfile.ZipFile(bundle, "r") as archive:
        for info in archive.infolist():
            if info.filename == MANIFEST_NAME:
                continue
            target = destination / PurePosixPath(info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info.filename))


def _candidate_is_clean(root: Path) -> bool:
    unstaged = subprocess.run(["git", "diff", "--quiet"], cwd=root).returncode == 0
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root).returncode == 0
    return unstaged and staged


def audit(root: Path, bundle_output: Path) -> dict:
    root = root.resolve()
    if not _candidate_is_clean(root):
        raise ValueError("Tracked source must be committed and clean before building the release bundle")
    revision = _run_git(root, "rev-parse", "HEAD")
    with tempfile.TemporaryDirectory(prefix="drastha-sprint26-") as directory:
        temporary = Path(directory)
        first = temporary / "first.zip"
        second = temporary / "second.zip"
        first_result = build_bundle(root, first, source_revision=revision)
        second_result = build_bundle(root, second, source_revision=revision)
        deterministic = first.read_bytes() == second.read_bytes()
        if not deterministic:
            raise ValueError("Two builds from the same source were not byte-identical")
        extracted = temporary / "extracted"
        extracted.mkdir()
        _extract_verified(first, extracted)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(extracted / "src")
        release_report = extracted / "output" / "sprint25-extracted-audit.json"
        release = subprocess.run(
            [sys.executable, str(extracted / "scripts" / "check_sprint25_release.py"),
             "--repo-root", str(extracted), "--report-output", str(release_report)],
            cwd=extracted, env=environment, capture_output=True, text=True,
        )
        if release.returncode != 0:
            raise RuntimeError(f"Extracted release audit failed: {release.stderr or release.stdout}")
        release_payload = json.loads(release_report.read_text(encoding="utf-8"))
        rehearsal_report = extracted / "output" / "sprint26-rehearsal.json"
        rehearsal = subprocess.run(
            [sys.executable, "-m", "aegisflow.cli", "demo-rehearse",
             "--root", str(extracted), "--evaluation-iterations", "1",
             "--report-output", str(rehearsal_report)],
            cwd=extracted, env=environment, capture_output=True, text=True,
        )
        if rehearsal.returncode != 0:
            raise RuntimeError(f"Extracted demo rehearsal failed: {rehearsal.stderr or rehearsal.stdout}")
        rehearsal_payload = json.loads(rehearsal_report.read_text(encoding="utf-8"))
        archive_unchanged = sha256(first.read_bytes()).hexdigest() == first_result["sha256"]
        if bundle_output.exists():
            raise FileExistsError(f"Bundle output already exists: {bundle_output}")
        bundle_output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(first, bundle_output)
    final = verify_bundle(bundle_output)
    try:
        final["path"] = bundle_output.resolve().relative_to(root).as_posix()
    except ValueError:
        final["path"] = bundle_output.name
    gates = {
        "tracked_candidate_clean": True,
        "two_builds_byte_identical": deterministic,
        "embedded_inventory_verified": final["passed"],
        "exact_source_revision": final["source_revision"] == revision,
        "prebuilt_dashboard_included": final["frontend_prebuilt"],
        "dependencies_honestly_excluded": final["dependencies_included"] is False,
        "extracted_sprint25_release_passed": release_payload["passed"],
        "extracted_demo_rehearsal_passed": rehearsal_payload["ready"],
        "double_replay_idempotent": rehearsal_payload["checks"]["replay_is_idempotent"],
        "archive_unchanged_by_rehearsal": archive_unchanged,
    }
    return {
        "schema_version": "drastha-sprint26-bundle-audit-v1",
        "passed": all(gates.values()),
        "gates": gates,
        "bundle": final,
        "rehearsal_checks": rehearsal_payload["checks"],
        "submission_demo_ready": all(gates.values()),
        "production_ready": False,
        "limitations": [
            "The bundle reuses the prepared host's Python runtime and installed API dependencies.",
            "Prebuilt dashboard assets are included; Node dependencies and a Node runtime are not included.",
            "The isolated-directory rehearsal is not a different OS, clean VM, live mirror or hardware data diode test.",
            "The archive contains synthetic demo/evaluation evidence and is not a production deployment package.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Choose a new report output path")
    report = audit(args.repo_root, args.bundle_output)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "bundle": report["bundle"],
                      "report": str(args.report_output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
