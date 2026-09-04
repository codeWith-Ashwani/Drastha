"""Local operator CLI. No network-facing backup/restore endpoints."""
import argparse
import json
import os
import sqlite3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.operations import backup_database, restore_database, preflight, read_key, read_json, verify_database


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-store", help="Create a fresh signed analyst database in a NEW directory")
    init.add_argument("--directory", type=Path, required=True)
    init.add_argument("--audit-key", type=Path, required=True)
    for name in ("verify", "backup"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--database", type=Path, required=True)
        cmd.add_argument("--audit-key", type=Path, required=True)
        if name == "backup":
            cmd.add_argument("--destination", type=Path, required=True)
        else:
            cmd.add_argument("--expected-head", type=Path)
    restore = commands.add_parser("restore", help="Verify and restore into a NEW directory; never cut over automatically")
    restore.add_argument("--bundle", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--audit-key", type=Path, required=True)
    restore.add_argument("--expected-head", type=Path, required=True)
    for name in ("stream-backup", "stream-check", "stream-restore"):
        cmd = commands.add_parser(name, help="Coordinated same-engine recovery; never automatic cutover")
        cmd.add_argument("--source", type=Path, required=True)
        cmd.add_argument("--audit-key", type=Path, required=True)
        cmd.add_argument("--root", type=Path, default=ROOT)
        cmd.add_argument("--model", type=Path)
        cmd.add_argument("--profile", choices=("deployment-baseline", "upload-demo", "stream-demo"), default="deployment-baseline")
        if name == "stream-backup":
            cmd.add_argument("--journal", type=Path, required=True)
            cmd.add_argument("--database", type=Path, required=True)
        else:
            cmd.add_argument("--bundle", type=Path, required=True)
            cmd.add_argument("--expected-anchor", type=Path, required=True)
        if name != "stream-check":
            cmd.add_argument("--destination", type=Path, required=True)
    for name in ("preflight", "serve"):
        cmd = commands.add_parser(name)
        for option in ("database", "audit-key", "auth", "cert", "tls-key", "web"):
            cmd.add_argument("--" + option, type=Path, required=True)
        cmd.add_argument("--root", type=Path, default=ROOT)
        cmd.add_argument("--host", default="127.0.0.1")
        cmd.add_argument("--port", type=int, default=8443)
    args = parser.parse_args(argv)
    try:
        key = read_key(args.audit_key)
        if args.command.startswith("stream-"):
            from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE, UPLOAD_DEMO, STREAM_DEMO
            from aegisflow.stream_recovery import backup_stream, restore_stream, check_stream
            profile = {"deployment-baseline": DEPLOYMENT_BASELINE, "upload-demo": UPLOAD_DEMO,
                       "stream-demo": STREAM_DEMO}[args.profile]
            factory = lambda: AnalysisSession.from_root(args.root, profile, model_path=args.model)
            if args.command == "stream-backup":
                result = backup_stream(args.source, args.journal, args.database, args.destination, key, factory)
            elif args.command == "stream-check":
                result = check_stream(args.bundle, args.source, key, read_json(args.expected_anchor), factory)
            else:
                result = restore_stream(args.bundle, args.source, args.destination, key, read_json(args.expected_anchor), factory)
        elif args.command == "init-store":
            args.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            result = AuditedIncidentRepository(args.directory / "analyst.db", key).verify_evidence()
        elif args.command == "verify":
            result = verify_database(args.database, key, read_json(args.expected_head) if args.expected_head else None)
        elif args.command == "backup":
            result = backup_database(args.database, args.destination, key)
        elif args.command == "restore":
            result = restore_database(args.bundle, args.destination, key, read_json(args.expected_head))
        else:
            options = {name: value for name, value in vars(args).items() if name != "command"}
            result = preflight(**options)
            if args.command == "serve":
                # Only this explicit command enables protected mode, in this process.
                os.environ.update(DRASTHA_DB=str(args.database.resolve()), DRASTHA_AUTH_MODE="required",
                                  DRASTHA_AUTH_FILE=str(args.auth.resolve()), DRASTHA_AUDIT_KEY_FILE=str(args.audit_key.resolve()),
                                  DRASTHA_ROOT=str(args.root.resolve()), DRASTHA_WEB=str(args.web.resolve()),
                                  DRASTHA_ANALYSIS_PROFILE="deployment-baseline")
                import uvicorn
                print(json.dumps(result), flush=True)
                uvicorn.run("aegisflow.api:app", host=args.host, port=args.port, proxy_headers=False,
                            workers=1, reload=False, ssl_certfile=str(args.cert.resolve()),
                            ssl_keyfile=str(args.tls_key.resolve()), access_log=False)
                return 0
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, sqlite3.Error) as exc:
        print(f"Operation refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
