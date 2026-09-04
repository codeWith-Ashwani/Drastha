from __future__ import annotations

import json
import os
import time
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

from aegisflow.api_store import IncidentRepository, read_jsonl, repository_from_url
from aegisflow.demo import run_attack_story
from aegisflow.upload_analysis import analyse_uploaded_replay
from aegisflow.streaming_demo import stream_simulated_ip_traffic
from aegisflow.analysis_session import configured_profile, UPLOAD_DEMO, STREAM_DEMO
from aegisflow.security import AccessSettings, AccessMiddleware
from aegisflow.audited_store import AuditedIncidentRepository, EvidenceIntegrityError


class StatusUpdate(BaseModel):
    status: str


class FeedbackRequest(BaseModel):
    disposition: str
    analyst: str = Field(min_length=1, max_length=80)
    notes: str = Field(default="", max_length=1000)


class ReplayUploadRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=5_000_000)


class RetentionRequest(BaseModel):
    before: float
    plan_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class RetentionHold(BaseModel):
    held: bool


def _repository() -> IncidentRepository:
    database = os.getenv("DRASTHA_DB") or os.getenv("AEGISFLOW_DB", "output/drastha.db")
    return repository_from_url(database)


def _load_demo(repository: IncidentRepository, root: Path) -> dict[str, int]:
    incidents = read_jsonl(root / "output/sprint4_incidents.jsonl")
    alerts = []
    for name in ("sprint3_c2_alerts.jsonl", "sprint4_exfil_alerts.jsonl"):
        alerts.extend(read_jsonl(root / "output" / name))
    feedback_path = root / "output/sprint4_feedback.json"
    feedback = [json.loads(feedback_path.read_text(encoding="utf-8"))]
    return repository.import_records(incidents, alerts, feedback)


def create_app(repository: IncidentRepository | None = None, *, access: AccessSettings | None = None) -> FastAPI:
    settings = access or AccessSettings.from_environment()
    if settings.mode == "required" and repository is None and not os.getenv("DRASTHA_AUDIT_KEY_FILE"):
        raise ValueError("Protected mode requires DRASTHA_AUDIT_KEY_FILE before opening a repository")
    store = repository or _repository()
    if settings.mode == "required" and not isinstance(store, AuditedIncidentRepository):
        raise ValueError("Protected mode requires a signed SQLite evidence store and external audit key")
    app = FastAPI(
        title="Drastha Analyst API",
        version="0.2.0",
        description="Offline-first incident review API for passive network monitoring.",
    )
    app.state.repository = store
    app.state.demo_run = None
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(AccessMiddleware, settings=settings)

    @app.exception_handler(EvidenceIntegrityError)
    async def integrity_failure(request: Request, exc: EvidenceIntegrityError):
        return JSONResponse({"detail": "Evidence integrity verification failed; operator review required"}, status_code=503)

    def signed_admin_store():
        if settings.mode != "required" or not isinstance(store, AuditedIncidentRepository):
            raise HTTPException(status_code=403, detail="Protected administrator mode required")
        return store

    @app.get("/api/security/audit")
    def verify_audit():
        return signed_admin_store().verify_evidence()

    @app.get("/api/security/retention")
    def preview_retention(before: float):
        try:
            return signed_admin_store().retention_plan(before)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/security/retention")
    def apply_retention(request: RetentionRequest):
        try:
            return signed_admin_store().apply_retention(request.before, request.plan_sha256)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.put("/api/security/retention/holds/{run_id}")
    def retention_hold(run_id: str, request: RetentionHold):
        try:
            signed_admin_store().set_retention_hold(run_id, request.held)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="analysis run not found") from exc
        return {"run_id": run_id, "held": request.held}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "mode": "passive_offline",
            "access_mode": settings.mode,
            "evidence_integrity": "hmac-verified-on-access" if isinstance(store, AuditedIncidentRepository) else "unsigned-demo",
            "return_path_required": False,
            "storage": "postgresql" if hasattr(store, "database_url") else "sqlite",
            "timestamp": time.time(),
            "demo_run": app.state.demo_run,
        }

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return store.metrics()

    @app.get("/api/analysis-runs/{run_id}")
    def analysis_run(run_id: str) -> dict[str, Any]:
        report = store.get_analysis_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail="analysis run not found")
        return report

    @app.get("/api/incidents")
    def incidents(
        status: str | None = Query(default=None),
        severity: str | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        return store.list_incidents(status=status, severity=severity)

    @app.get("/api/incidents/{incident_id}")
    def incident_detail(incident_id: str) -> dict[str, Any]:
        incident = store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident

    @app.patch("/api/incidents/{incident_id}/status")
    def update_status(incident_id: str, request: StatusUpdate) -> dict[str, Any]:
        try:
            updated = store.set_status(incident_id, request.status, time.time())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not updated:
            raise HTTPException(status_code=404, detail="incident not found")
        return {"incident_id": incident_id, "status": request.status}

    @app.post("/api/incidents/{incident_id}/feedback", status_code=201)
    def add_feedback(incident_id: str, request: FeedbackRequest, http_request: Request) -> dict[str, Any]:
        timestamp = time.time()
        principal = http_request.scope.get("drastha_principal")
        analyst = principal.principal if principal else request.analyst
        identity = f"{incident_id}|{analyst}|{timestamp:.6f}|{request.disposition}"
        record = {
            "feedback_id": sha256(identity.encode("utf-8")).hexdigest()[:20],
            "incident_id": incident_id,
            "disposition": request.disposition,
            "analyst": analyst,
            "timestamp": timestamp,
            "notes": request.notes,
        }
        try:
            return store.add_feedback(record)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/incidents/{incident_id}/export")
    def export_incident(incident_id: str) -> dict[str, Any]:
        incident = store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        payload = {
            "format": "drastha-incident-v1",
            "exported_at": time.time(),
            "incident": incident,
        }
        return {**payload, "integrity": store.sign_export(payload) if isinstance(store, AuditedIncidentRepository) else None}

    @app.post("/api/demo/load")
    def load_demo() -> dict[str, Any]:
        root = Path(os.getenv("DRASTHA_ROOT") or os.getenv("AEGISFLOW_ROOT", Path.cwd()))
        try:
            loaded = _load_demo(store, root)
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"demo files unavailable: {exc}") from exc
        return {"loaded": loaded, "metrics": store.metrics()}

    @app.post("/api/demo/run")
    def run_demo() -> dict[str, Any]:
        root = Path(os.getenv("DRASTHA_ROOT") or os.getenv("AEGISFLOW_ROOT", Path.cwd()))
        report = run_attack_story(root, store)
        app.state.demo_run = {
            "status": report["status"],
            "telemetry_status": report.get("telemetry_status", "unavailable"),
            "elapsed_ms": report.get("elapsed_ms"),
            "stages": report.get("stages", []),
        }
        if report["status"] != "completed":
            raise HTTPException(status_code=503, detail=report["reason"])
        return report

    @app.post("/api/replays/analyse")
    def analyse_replay(request: ReplayUploadRequest) -> dict[str, Any]:
        try:
            report = analyse_uploaded_replay(request.filename, request.content, store,
                                             profile=configured_profile(UPLOAD_DEMO))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        app.state.demo_run = {
            "status": report["status"],
            "telemetry_status": report["quality"]["status"],
            "elapsed_ms": report["analysis_ms"],
            "stages": report["stages"],
        }
        return report

    @app.get("/api/replays/sample", response_class=FileResponse)
    def sample_replay() -> FileResponse:
        root = Path(os.getenv("DRASTHA_ROOT") or os.getenv("AEGISFLOW_ROOT", Path.cwd()))
        sample = root / "examples" / "judge_attack_replay.jsonl"
        if not sample.is_file():
            raise HTTPException(status_code=404, detail="sample replay unavailable")
        return FileResponse(sample, filename="drastha-judge-attack-replay.jsonl")

    @app.get("/api/stream/simulated")
    def simulated_stream(
        interval: float = Query(default=0.10, ge=0.0, le=1.0),
    ) -> StreamingResponse:
        root = Path(os.getenv("DRASTHA_ROOT") or os.getenv("AEGISFLOW_ROOT", Path.cwd()))
        try:
            profile = configured_profile(STREAM_DEMO)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return StreamingResponse(
            stream_simulated_ip_traffic(root, store, interval_seconds=interval, profile=profile),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "X-Drastha-Passive": "true",
            },
        )

    frontend = Path(os.getenv("DRASTHA_WEB") or os.getenv("AEGISFLOW_WEB", "web/dist"))
    if frontend.exists():
        @app.get("/{path:path}", include_in_schema=False)
        def dashboard(path: str) -> FileResponse:
            candidate = (frontend / path).resolve()
            if path and candidate.is_file() and frontend.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(frontend / "index.html")

    return app


app = create_app()
