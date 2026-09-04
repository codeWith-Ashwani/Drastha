"""Create-only bootstrap for a NEW protected SQLite deployment.

Run in an owner-only directory. Never print plaintext secrets or overwrite keys.
This does not turn on security, issue TLS certificates or migrate old evidence.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.security import AccessSettings, Credential


def bootstrap(directory, origin, lifetime_seconds=86400):
    if not 300 <= lifetime_seconds <= 30 * 86400:
        raise ValueError("Credential lifetime must be 5 minutes to 30 days")
    expires = time.time() + lifetime_seconds
    tokens = {role: secrets.token_urlsafe(32) for role in ("viewer", "analyst", "admin")}
    credentials = tuple(Credential(role, role, sha256(token.encode()).hexdigest(), expires)
                        for role, token in tokens.items())
    AccessSettings("required", credentials, (origin,))
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = {"auth.json": json.dumps({"credentials": [c.__dict__ for c in credentials],
                                      "allowed_origins": [origin]}, indent=2),
             "audit.key": secrets.token_hex(32),
             "bootstrap-tokens.json": json.dumps({"expires_at": expires, "tokens": tokens}, indent=2)}
    for name, content in files.items():
        path = directory / name
        # POSIX mode is defense-in-depth; Windows requires owner-only inherited ACLs.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content + "\n")
    return {"directory": str(directory.resolve()), "files": list(files),
            "expires_at": expires, "security_enabled": False,
            "note": "Restrict Windows ACLs; distribute bootstrap tokens privately and retain audit key separately from the database"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--origin", required=True, help="Exact trusted HTTPS dashboard origin")
    parser.add_argument("--lifetime-seconds", type=int, default=86400)
    args = parser.parse_args()
    try:
        print(json.dumps(bootstrap(args.directory, args.origin, args.lifetime_seconds)))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Security bootstrap failed: {exc}\n")
