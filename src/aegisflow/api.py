from __future__ import annotations

import json
import os
import time
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from aegisflow.api_store import IncidentRepository, read_jsonl, repository_from_url
from aegisflow.demo import run_attack_story


class StatusUpdate(BaseModel):
    status: str


class FeedbackRequest(BaseModel):
    disposition: str
    analyst: str = Field(min_length=1, max_length=80)
    notes: str = Field(default="", max_length=1000)


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


def create_app(repository: IncidentRepository | None = None) -> FastAPI:
    store = repository or _repository()
    app = FastAPI(
        title="Drastha Analyst API",
        version="0.2.0",
        description="Offline-first incident review API for passive network monitoring.",
    )
    app.state.repository = store
    app.state.demo_run = None
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "mode": "passive_offline",
            "return_path_required": False,
            "storage": "postgresql" if hasattr(store, "database_url") else "sqlite",
            "timestamp": time.time(),
            "demo_run": app.state.demo_run,
        }

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return store.metrics()

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
    def add_feedback(incident_id: str, request: FeedbackRequest) -> dict[str, Any]:
        timestamp = time.time()
        identity = f"{incident_id}|{request.analyst}|{timestamp:.6f}|{request.disposition}"
        record = {
            "feedback_id": sha256(identity.encode("utf-8")).hexdigest()[:20],
            "incident_id": incident_id,
            "disposition": request.disposition,
            "analyst": request.analyst,
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
        return {
            "format": "drastha-incident-v1",
            "exported_at": time.time(),
            "incident": incident,
        }

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
