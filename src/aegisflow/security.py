"""Explicit token-based access for the monitoring-side analyst application.

Opaque random tokens, not human passwords. No login cookies, source callbacks,
tokens in URLs, or custom JWT implementation. Local demo mode remains explicit.
"""
from __future__ import annotations

import base64
import binascii
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import math
import os
from pathlib import Path
import re
import time

from starlette.responses import JSONResponse


audit_actor = ContextVar("audit_actor", default="system:local-worker")
audit_operation = ContextVar("audit_operation", default="repository")


@dataclass(frozen=True)
class Credential:
    principal: str
    role: str
    token_sha256: str
    expires_at: float


@dataclass(frozen=True)
class AccessSettings:
    mode: str = "local-demo"
    credentials: tuple[Credential, ...] = ()
    allowed_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")

    def __post_init__(self):
        if self.mode not in {"local-demo", "required"}:
            raise ValueError("DRASTHA_AUTH_MODE must be local-demo or required")
        if self.mode == "required" and not self.credentials:
            raise ValueError("Protected mode requires configured credentials")
        names, hashes = set(), set()
        for credential in self.credentials:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", credential.principal):
                raise ValueError("Invalid principal")
            if credential.role not in {"viewer", "analyst", "admin"}:
                raise ValueError("Invalid access role")
            if not re.fullmatch(r"[a-f0-9]{64}", credential.token_sha256):
                raise ValueError("Credentials must contain SHA-256 token digests, not plaintext")
            if not math.isfinite(credential.expires_at) or credential.expires_at <= 0:
                raise ValueError("Credentials require finite expiry timestamps")
            if credential.principal in names or credential.token_sha256 in hashes:
                raise ValueError("Duplicate credential identity/token")
            names.add(credential.principal)
            hashes.add(credential.token_sha256)
        from urllib.parse import urlsplit
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                    parsed.path or parsed.query or parsed.fragment or parsed.username or
                    "*" in origin or (self.mode == "required" and parsed.scheme != "https")):
                raise ValueError("Allowed origins must be exact HTTP(S) origins")

    @classmethod
    def from_environment(cls):
        mode = os.getenv("DRASTHA_AUTH_MODE", "local-demo")
        path = os.getenv("DRASTHA_AUTH_FILE")
        if mode == "local-demo":
            if path:
                raise ValueError("Auth file configured but required authentication is not enabled")
            return cls(mode=mode)
        if mode != "required" or not path:
            raise ValueError("Protected mode requires DRASTHA_AUTH_FILE")
        return cls.from_file(path)

    @classmethod
    def from_file(cls, path):
        """Load explicit protected configuration without mutating environment."""
        config_path = Path(path)
        if config_path.stat().st_size > 65_536:
            raise ValueError("Auth configuration too large")
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            credentials = tuple(Credential(**item) for item in config["credentials"])
            origins = tuple(config.get("allowed_origins", ()))
            return cls("required", credentials, origins)
        except (KeyError, TypeError) as exc:
            raise ValueError("Malformed auth configuration") from exc


def load_audit_key():
    path = os.getenv("DRASTHA_AUDIT_KEY_FILE")
    if not path:
        return None
    if Path(path).stat().st_size > 256:
        raise ValueError("Audit key file is too large")
    raw = Path(path).read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", raw):
        raise ValueError("Audit key file must contain exactly 32 random bytes as 64 hex characters")
    return bytes.fromhex(raw)


class AccessMiddleware:
    def __init__(self, app, settings: AccessSettings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket" and self.settings.mode == "required":
            return await send({"type": "websocket.close", "code": 4401})
        if scope["type"] != "http" or self.settings.mode == "local-demo":
            return await self.app(scope, receive, send)
        headers = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.lower(), []).append(value)

        async def deny(code, detail):
            response = JSONResponse({"detail": detail}, status_code=code,
                                    headers={"WWW-Authenticate": 'Basic realm="Drastha", charset="UTF-8"',
                                             "Cache-Control": "no-store"})
            await response(scope, receive, send)

        if scope.get("scheme") != "https":
            return await deny(403, "Protected mode requires HTTPS")
        # Only CORS preflights may bypass credentials; they cannot run a route.
        if scope["method"] == "OPTIONS" and b"access-control-request-method" in headers:
            return await self.app(scope, receive, send)
        values = headers.get(b"authorization", [])
        if len(values) != 1 or len(values[0]) > 2048:
            return await deny(401, "Authentication required")
        basic_name = None
        try:
            scheme, token = values[0].decode("ascii").split(" ", 1)
            if scheme.lower() == "basic":
                basic_name, token = base64.b64decode(token, validate=True).decode("utf-8").split(":", 1)
            elif scheme.lower() != "bearer":
                raise ValueError("Unsupported scheme")
            if not 32 <= len(token) <= 512:
                raise ValueError("Invalid token length")
        except (ValueError, UnicodeError, binascii.Error):
            return await deny(401, "Authentication required")
        digest = sha256(token.encode()).hexdigest()
        principal = None
        for credential in self.settings.credentials:
            matched = compare_digest(digest, credential.token_sha256)
            named = basic_name is None or compare_digest(basic_name.encode(), credential.principal.encode())
            if matched and named and time.time() < credential.expires_at:
                principal = credential
        if principal is None:
            return await deny(401, "Authentication required")
        path = scope.get("path", "")
        mutates = scope["method"] not in {"GET", "HEAD", "OPTIONS"} or path.rstrip("/") == "/api/stream/simulated"
        if path.startswith("/api/security/") and principal.role != "admin":
            return await deny(403, "Administrator access required")
        if mutates and principal.role == "viewer":
            return await deny(403, "Analyst access required")
        # Basic credentials are browser-ambient. Protect even the legacy mutating GET.
        if mutates and basic_name is not None:
            origins = headers.get(b"origin", [])
            site = headers.get(b"sec-fetch-site", [])
            same_origin = not origins and site == [b"same-origin"]
            allowed = len(origins) == 1 and origins[0].decode("latin-1") in self.settings.allowed_origins
            if not (same_origin or allowed):
                return await deny(403, "Trusted browser origin required")
        scope["drastha_principal"] = principal
        actor = audit_actor.set(principal.principal)
        operation = audit_operation.set(scope["method"] + " " + path[:200])

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = [*(message.get("headers", [])),
                                      (b"cache-control", b"no-store"),
                                      (b"x-content-type-options", b"nosniff"),
                                      (b"x-frame-options", b"DENY"),
                                      (b"referrer-policy", b"no-referrer")]
            await send(message)
        try:
            return await self.app(scope, receive, secure_send)
        finally:
            audit_actor.reset(actor)
            audit_operation.reset(operation)
