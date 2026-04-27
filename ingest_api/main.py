from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from sqlalchemy.orm import Session

from ingest_api.config import get_settings
from ingest_api.database import get_db
from ingest_api.metrics import INGEST_FAILURES, INGEST_LATENCY, INGEST_REQUESTS
from ingest_api.models import Artifact, CredentialAttempt, Detection, Event, Investigation
from ingest_api.object_store import get_bytes
from ingest_api.schemas import (
    ArtifactOut,
    BlocklistExportRequest,
    CredentialOut,
    DetectionOut,
    DetectionUpdateIn,
    EventOut,
    EvidenceExportRequest,
    ExportRequest,
    FleetOut,
    HeartbeatIn,
    InvestigationOut,
    IngestEventIn,
    PostureOut,
    render_csv,
)
from ingest_api.security import AnalystIdentity, require_analyst_identity, require_ingest_key
from ingest_api.services import (
    build_blocklist_export,
    build_evidence_export,
    build_management_summary_export,
    create_artifact_record,
    insert_event,
    list_block_targets,
    materialize_detections,
    query_fleet,
    query_overview,
    query_posture,
    refresh_fleet_health,
    upsert_heartbeat,
)


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.2.0")

allowed_origins = [
    settings.web_origin,
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def artifact_to_out(artifact: Artifact) -> ArtifactOut:
    return ArtifactOut(
        id=artifact.id,
        artifact_type=artifact.artifact_type,
        export_format=artifact.export_format,
        generated_by=artifact.generated_by,
        generated_at=artifact.generated_at,
        bucket=artifact.bucket,
        object_key=artifact.object_key,
        linked_investigation=artifact.linked_investigation,
        download_url=f"/api/v1/exports/{artifact.id}/download",
    )


@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "environment": settings.environment, "version": settings.collector_version}


@app.get("/health")
def legacy_health(db: Session = Depends(get_db)) -> dict[str, Any]:
    return health(db)


@app.get("/api/v1/metrics")
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _handle_ingest(payload: IngestEventIn, db: Session) -> dict[str, Any]:
    INGEST_REQUESTS.inc()
    with INGEST_LATENCY.time():
        try:
            event = insert_event(db, payload)
            db.commit()
            if settings.inline_alert_processing:
                materialize_detections(db, limit=200)
                db.commit()
            return {"status": "stored", "event_id": event.event_id}
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            INGEST_FAILURES.inc()
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/events")
def ingest_event(
    payload: IngestEventIn,
    _: None = Depends(require_ingest_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _handle_ingest(payload, db)


@app.post("/event")
def legacy_ingest_event(payload: IngestEventIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _handle_ingest(payload, db)


@app.post("/api/v1/heartbeats")
def ingest_heartbeat(
    payload: HeartbeatIn,
    _: None = Depends(require_ingest_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        decoy = upsert_heartbeat(db, payload)
        db.commit()
        return {"status": "stored", "decoy_id": decoy.decoy_id}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/heartbeat")
def ingest_heartbeat_compat(
    payload: HeartbeatIn,
    _: None = Depends(require_ingest_key),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return ingest_heartbeat(payload=payload, _=_, db=db)


@app.get("/api/v1/stats/posture", response_model=PostureOut)
def posture(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> PostureOut:
    data = query_posture(db)
    recent = [DetectionOut.model_validate(item, from_attributes=True) for item in data["recent_detections"]]
    payload = {**data, "recent_detections": recent}
    return PostureOut(**payload)


@app.get("/api/v1/stats/overview")
def overview_compat(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    summary = query_overview(db)
    recent_alerts = [DetectionOut.model_validate(alert, from_attributes=True).model_dump(mode="json") for alert in summary["recent_alerts"]]
    return {**summary, "recent_alerts": recent_alerts}


@app.get("/api/v1/events", response_model=list[EventOut])
def list_events(
    suspicious: bool | None = Query(default=None),
    decoy_id: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    path: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[EventOut]:
    query = db.query(Event).order_by(Event.occurred_at.desc())
    if suspicious is not None:
        query = query.filter(Event.suspicious.is_(suspicious))
    if decoy_id:
        query = query.filter(Event.decoy_id == decoy_id)
    if src_ip:
        query = query.filter(Event.src_ip == src_ip)
    if path:
        query = query.filter(Event.path == path)
    return [EventOut.model_validate(event, from_attributes=True) for event in query.limit(limit).all()]


@app.get("/api/v1/fleet", response_model=list[FleetOut])
def list_fleet(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[FleetOut]:
    refresh_fleet_health(db)
    rows = query_fleet(db)
    return [
        FleetOut(
            decoy_id=row.decoy_id,
            profile=row.profile,
            edge_node_id=row.edge_node_id,
            decoy_version=row.decoy_version,
            collector_version=row.collector_version,
            public_endpoint=row.public_endpoint,
            status=row.status,
            health_status=row.health_status,
            coverage_role=row.coverage_role,
            environment=row.environment,
            site=row.site,
            last_seen_at=row.last_seen_at,
            last_heartbeat_at=row.last_heartbeat_at,
            runtime_state=(row.deployments[-1].runtime_state if row.deployments else "unknown"),
            failure_reason=(row.deployments[-1].failure_reason if row.deployments else None),
            relay_health=((row.deployments[-1].metadata_json or {}).get("relay_health") if row.deployments else None),
            relay_queue_backlog=((row.deployments[-1].metadata_json or {}).get("relay_queue_backlog") if row.deployments else None),
        )
        for row in rows
    ]


@app.get("/api/v1/decoys", response_model=list[FleetOut])
def list_decoys_compat(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[FleetOut]:
    return list_fleet(_, db)


@app.get("/api/v1/fleet/coverage")
def fleet_coverage(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    fleet = query_fleet(db)
    coverage_gaps = sorted({decoy.site for decoy in fleet if decoy.health_status == "silent"})
    return {
        "coverage_gaps": coverage_gaps,
        "healthy": sum(1 for decoy in fleet if decoy.health_status == "healthy"),
        "degraded": sum(1 for decoy in fleet if decoy.health_status == "degraded"),
        "silent": sum(1 for decoy in fleet if decoy.health_status == "silent"),
    }


@app.get("/api/v1/detections", response_model=list[DetectionOut])
def list_detections(
    status: str = Query(default="all"),
    severity: str | None = Query(default=None),
    detection_type: str | None = Query(default=None),
    site: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[DetectionOut]:
    query = db.query(Detection).order_by(Detection.last_seen_at.desc())
    if status != "all":
        query = query.filter(Detection.status == status)
    if severity:
        query = query.filter(Detection.severity == severity)
    if detection_type:
        query = query.filter(Detection.detection_type == detection_type)
    if site:
        query = query.filter(Detection.site == site)
    if src_ip:
        query = query.filter(Detection.src_ip == src_ip)
    return [DetectionOut.model_validate(row, from_attributes=True) for row in query.limit(300).all()]


@app.get("/api/v1/alerts", response_model=list[DetectionOut])
def list_alerts_compat(
    status: str = Query(default="all"),
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[DetectionOut]:
    return list_detections(status=status, severity=None, detection_type=None, site=None, src_ip=None, _=_, db=db)


@app.get("/api/v1/detections/{detection_id}", response_model=DetectionOut)
def get_detection(
    detection_id: str,
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> DetectionOut:
    row = db.query(Detection).filter(Detection.id == detection_id).one()
    return DetectionOut.model_validate(row, from_attributes=True)


@app.patch("/api/v1/detections/{detection_id}", response_model=DetectionOut)
def update_detection(
    detection_id: str,
    request: DetectionUpdateIn,
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> DetectionOut:
    row = db.query(Detection).filter(Detection.id == detection_id).one()
    if request.status is not None:
        row.status = request.status
    if request.assigned_to is not None:
        row.assigned_to = request.assigned_to
    if request.triage_notes is not None:
        row.triage_notes = request.triage_notes
    db.commit()
    db.refresh(row)
    return DetectionOut.model_validate(row, from_attributes=True)


@app.get("/api/v1/investigations", response_model=list[InvestigationOut])
def list_investigations(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[InvestigationOut]:
    rows = db.query(Investigation).order_by(Investigation.last_seen.desc()).limit(200).all()
    return [InvestigationOut.model_validate(row, from_attributes=True) for row in rows]


@app.get("/api/v1/investigations/{investigation_id}", response_model=InvestigationOut)
def get_investigation(
    investigation_id: str,
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> InvestigationOut:
    row = db.query(Investigation).filter(Investigation.id == investigation_id).one()
    return InvestigationOut.model_validate(row, from_attributes=True)


@app.post("/api/v1/investigations/from-detection/{detection_id}", response_model=InvestigationOut)
def investigation_from_detection(
    detection_id: str,
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> InvestigationOut:
    detection = db.query(Detection).filter(Detection.id == detection_id).one()
    if detection.investigation is None:
        raise HTTPException(status_code=404, detail="detection has no investigation")
    return InvestigationOut.model_validate(detection.investigation, from_attributes=True)


@app.get("/api/v1/credentials", response_model=list[CredentialOut])
def list_credentials(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[CredentialOut]:
    rows = (
        db.query(CredentialAttempt, Event.event_id)
        .join(Event, Event.id == CredentialAttempt.event_pk)
        .order_by(CredentialAttempt.attempted_at.desc())
        .limit(200)
        .all()
    )
    return [
        CredentialOut(
            id=credential.id,
            attempted_at=credential.attempted_at,
            decoy_id=credential.decoy_id,
            src_ip=credential.src_ip,
            username=credential.username,
            password=credential.password,
            event_id=event_id,
        )
        for credential, event_id in rows
    ]


@app.get("/api/v1/blocklists")
def get_blocklists(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return {"entries": list_block_targets(db)}


@app.post("/api/v1/blocklists/export", response_model=ArtifactOut)
def export_blocklist(
    request: BlocklistExportRequest,
    identity: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> ArtifactOut:
    artifact = build_blocklist_export(db, request, identity.subject)
    db.commit()
    return artifact_to_out(artifact)


@app.get("/api/v1/exports", response_model=list[ArtifactOut])
def list_exports(
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> list[ArtifactOut]:
    rows = db.query(Artifact).order_by(Artifact.generated_at.desc()).limit(100).all()
    return [artifact_to_out(row) for row in rows]


@app.post("/api/v1/exports/evidence", response_model=ArtifactOut)
def export_evidence(
    request: EvidenceExportRequest,
    identity: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> ArtifactOut:
    artifact = build_evidence_export(db, request, identity.subject)
    db.commit()
    return artifact_to_out(artifact)


@app.post("/api/v1/reports/export", response_model=ArtifactOut)
def export_management_summary(
    request: ExportRequest,
    identity: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> ArtifactOut:
    if request.format == "html":
        artifact = build_management_summary_export(db, identity.subject)
        db.commit()
        return artifact_to_out(artifact)

    events = db.query(Event).order_by(Event.occurred_at.desc()).limit(request.limit).all()
    rows = [
        {
            "occurred_at": event.occurred_at.isoformat(),
            "decoy_id": event.decoy_id,
            "profile": event.profile,
            "site": event.site,
            "src_ip": event.src_ip,
            "method": event.method,
            "path": event.path,
            "status_code": event.status_code,
            "event_class": event.event_class,
            "username": event.username,
            "password": event.password,
            "suspicious": event.suspicious,
            "tags": event.normalized_tags,
        }
        for event in events
    ]
    payload = render_csv(rows).encode("utf-8")
    stored = create_artifact_record(
        db,
        artifact_type="management_summary",
        export_format="csv",
        generated_by=identity.subject,
        body=payload,
        content_type="text/csv",
    )
    db.commit()
    return artifact_to_out(stored)


@app.get("/api/v1/exports/{artifact_id}/download")
def download_export(
    artifact_id: str,
    _: AnalystIdentity = Depends(require_analyst_identity),
    db: Session = Depends(get_db),
) -> Response:
    artifact = db.query(Artifact).filter(Artifact.id == artifact_id).one()
    payload, content_type = get_bytes(artifact.bucket, artifact.object_key)
    extension = artifact.export_format
    return Response(
        content=payload,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={artifact.artifact_type}-{artifact.id}.{extension}"},
    )
