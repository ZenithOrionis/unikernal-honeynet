from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from ingest_api.config import get_settings
from ingest_api.models import Artifact, CredentialAttempt, Decoy, Deployment, Detection, Event, Investigation
from ingest_api.object_store import put_bytes
from ingest_api.schemas import BlocklistExportRequest, EvidenceExportRequest, HeartbeatIn, IngestEventIn


settings = get_settings()


SENSITIVE_PATHS = {"/admin", "/config", "/status", "/.env", "/backup", "/phpmyadmin"}
DETECTION_RULES = {
    "internet_recon": {
        "severity": "medium",
        "confidence": "medium",
        "action": "Block the source if reconnaissance persists and review perimeter logs for adjacent probing.",
    },
    "credential_bruteforce": {
        "severity": "high",
        "confidence": "high",
        "action": "Block the source IP and rotate exposed credentials on any matching internet-facing services.",
    },
    "credential_stuffing": {
        "severity": "critical",
        "confidence": "high",
        "action": "Immediately block the source and check IAM, VPN, and SSO logs for credential reuse attempts.",
    },
    "path_traversal_probe": {
        "severity": "high",
        "confidence": "high",
        "action": "Block the source and validate web tier path normalization controls.",
    },
    "xss_probe": {
        "severity": "medium",
        "confidence": "medium",
        "action": "Contain the source if repeated and review front-end sanitization or WAF telemetry.",
    },
    "sqli_probe": {
        "severity": "high",
        "confidence": "high",
        "action": "Block the source and review database-facing web services for matching indicators.",
    },
    "sensitive_path_discovery": {
        "severity": "medium",
        "confidence": "medium",
        "action": "Monitor for repeat attempts and check perimeter logs for access to sensitive administrative paths.",
    },
    "admin_panel_enumeration": {
        "severity": "high",
        "confidence": "medium",
        "action": "Block the source if the pattern continues and verify access controls on administrative endpoints.",
    },
    "distributed_scanner_activity": {
        "severity": "high",
        "confidence": "high",
        "action": "Block the source and search across branch, DMZ, and internet-edge logs for coordinated scanning.",
    },
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_tags(event: IngestEventIn) -> list[str]:
    tags = {tag.strip().lower() for tag in (event.normalized_tags or event.tags) if tag.strip()}
    path = (event.path or "").lower()
    body_fields = " ".join([event.username, event.password, path]).lower()
    if event.path in SENSITIVE_PATHS:
        tags.add("sensitive_path_discovery")
    if "/admin" in path or "/config" in path or "/status" in path:
        tags.add("admin_panel_enumeration")
    if "../" in body_fields:
        tags.add("path_traversal_probe")
    if "<script>" in body_fields:
        tags.add("xss_probe")
    if "union select" in body_fields:
        tags.add("sqli_probe")
    if event.method.upper() == "POST" and event.path == "/login":
        tags.add("credential_bruteforce")
    if not tags and event.suspicious:
        tags.add("internet_recon")
    return sorted(tags)


def classify_event(event: IngestEventIn, normalized_tags: list[str]) -> str:
    if any(tag in normalized_tags for tag in {"credential_bruteforce", "credential_stuffing"}):
        return "credential"
    if any(tag in normalized_tags for tag in {"sqli_probe", "xss_probe", "path_traversal_probe"}):
        return "probe"
    if any(tag in normalized_tags for tag in {"admin_panel_enumeration", "sensitive_path_discovery"}):
        return "recon"
    return "scan" if event.suspicious else "probe"


def generate_request_fingerprint(method: str, path: str, user_agent: str, normalized_tags: list[str]) -> str:
    raw = f"{method.upper()}|{path}|{user_agent[:80]}|{','.join(normalized_tags)}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def normalize_payload(payload: IngestEventIn) -> dict[str, Any]:
    occurred_at = payload.ts if isinstance(payload.ts, datetime) else utcnow()
    normalized_tags = normalize_tags(payload)
    return {
        "event_id": payload.event_id or str(uuid.uuid4()),
        "occurred_at": occurred_at,
        "decoy_id": payload.decoy_id.strip(),
        "profile": payload.profile.strip(),
        "src_ip": (payload.src_ip or "unknown").strip(),
        "method": payload.method,
        "path": payload.path.strip() or "/",
        "user_agent": payload.user_agent.strip(),
        "username": payload.username.strip(),
        "password": payload.password.strip(),
        "suspicious": bool(payload.suspicious),
        "tags": payload.tags,
        "normalized_tags": normalized_tags,
        "collector_version": payload.collector_version or settings.collector_version,
        "edge_node_id": payload.edge_node_id or "unknown-edge",
        "decoy_version": payload.decoy_version or "unknown",
        "status_code": payload.status_code or 0,
        "latency_ms": payload.latency_ms or 0,
        "headers_subset": payload.headers_subset or {},
        "public_endpoint": payload.public_endpoint,
        "request_fingerprint": payload.request_fingerprint
        or generate_request_fingerprint(payload.method, payload.path, payload.user_agent, normalized_tags),
        "source_country": payload.source_country,
        "event_class": payload.event_class or classify_event(payload, normalized_tags),
        "site": payload.site or "unknown",
        "environment": payload.environment or "unknown",
        "coverage_role": payload.coverage_role or "internet_edge",
        "raw_json": payload.model_dump(mode="json"),
    }


def reconcile_expected_fleet(db: Session) -> None:
    for expected in settings.expected_fleet():
        decoy_id = expected.get("decoy_id")
        if not decoy_id:
            continue
        decoy = db.query(Decoy).filter(Decoy.decoy_id == decoy_id).one_or_none()
        if decoy is None:
            decoy = Decoy(
                decoy_id=decoy_id,
                profile=expected.get("profile", "unknown"),
                edge_node_id=expected.get("edge_node_id", "inventory"),
                decoy_version=expected.get("decoy_version", "expected"),
                collector_version=settings.collector_version,
                public_endpoint=expected.get("public_endpoint"),
                status="expected",
                health_status="silent",
                coverage_role=expected.get("coverage_role", "internet_edge"),
                environment=expected.get("environment", "unknown"),
                site=expected.get("site", "unknown"),
            )
            db.add(decoy)
            db.flush()
        else:
            decoy.profile = expected.get("profile", decoy.profile)
            decoy.edge_node_id = expected.get("edge_node_id", decoy.edge_node_id)
            decoy.public_endpoint = expected.get("public_endpoint", decoy.public_endpoint)
            decoy.coverage_role = expected.get("coverage_role", decoy.coverage_role)
            decoy.environment = expected.get("environment", decoy.environment)
            decoy.site = expected.get("site", decoy.site)

        deployment = db.query(Deployment).filter(Deployment.decoy_id == decoy.id).order_by(Deployment.updated_at.desc()).first()
        if deployment is None:
            deployment = Deployment(
                decoy=decoy,
                edge_node_id=expected.get("edge_node_id", decoy.edge_node_id),
                profile=expected.get("profile", decoy.profile),
                runtime="unikraft-kvm",
                build_version=expected.get("decoy_version", decoy.decoy_version),
                public_endpoint=expected.get("public_endpoint"),
                status="expected",
                desired_state="running",
                observed_state="missing",
                host_port=expected.get("host_port"),
                runtime_state="not_reported",
                site=expected.get("site", decoy.site),
                environment=expected.get("environment", decoy.environment),
                coverage_role=expected.get("coverage_role", decoy.coverage_role),
                metadata_json={"inventory_managed": True},
            )
            db.add(deployment)
        else:
            deployment.edge_node_id = expected.get("edge_node_id", deployment.edge_node_id)
            deployment.profile = expected.get("profile", deployment.profile)
            deployment.build_version = expected.get("decoy_version", deployment.build_version)
            deployment.public_endpoint = expected.get("public_endpoint", deployment.public_endpoint)
            deployment.desired_state = "running"
            deployment.host_port = expected.get("host_port", deployment.host_port)
            deployment.site = expected.get("site", deployment.site)
            deployment.environment = expected.get("environment", deployment.environment)
            deployment.coverage_role = expected.get("coverage_role", deployment.coverage_role)
            deployment.metadata_json = {**(deployment.metadata_json or {}), "inventory_managed": True}
    db.flush()


def refresh_fleet_health(db: Session) -> None:
    now = utcnow()
    for decoy in db.query(Decoy).all():
        if decoy.last_heartbeat_at is None:
            decoy.health_status = "silent"
        else:
            age = (now - decoy.last_heartbeat_at).total_seconds()
            if age >= settings.heartbeat_silent_seconds:
                decoy.health_status = "silent"
            elif age >= settings.heartbeat_degraded_seconds:
                decoy.health_status = "degraded"
            else:
                decoy.health_status = "healthy"

        deployment = db.query(Deployment).filter(Deployment.decoy_id == decoy.id).order_by(Deployment.updated_at.desc()).first()
        if deployment is not None:
            deployment.observed_state = "running" if decoy.last_heartbeat_at else "missing"
            if decoy.health_status == "silent":
                deployment.runtime_state = "silent"
                if not deployment.failure_reason:
                    deployment.failure_reason = "Heartbeat missing"
            else:
                deployment.runtime_state = "running"
                deployment.failure_reason = None
    db.flush()


def _prefer_inventory_value(incoming: Any, existing: Any, placeholder: Any) -> Any:
    if incoming in {None, "", placeholder}:
        return existing if existing not in {None, ""} else placeholder
    return incoming


def upsert_decoy(db: Session, normalized: dict[str, Any]) -> Decoy:
    decoy = db.query(Decoy).filter(Decoy.decoy_id == normalized["decoy_id"]).one_or_none()
    if decoy is None:
        decoy = Decoy(
            decoy_id=normalized["decoy_id"],
            profile=normalized["profile"],
            edge_node_id=normalized["edge_node_id"],
            decoy_version=normalized["decoy_version"],
            collector_version=normalized["collector_version"],
            public_endpoint=normalized["public_endpoint"],
            status="active",
            coverage_role=normalized["coverage_role"],
            environment=normalized["environment"],
            site=normalized["site"],
        )
        db.add(decoy)
    else:
        decoy.profile = normalized["profile"]
        decoy.edge_node_id = _prefer_inventory_value(normalized["edge_node_id"], decoy.edge_node_id, "unknown-edge")
        decoy.decoy_version = _prefer_inventory_value(normalized["decoy_version"], decoy.decoy_version, "unknown")
        decoy.collector_version = normalized["collector_version"]
        decoy.public_endpoint = normalized["public_endpoint"] or decoy.public_endpoint
        decoy.status = "active"
        decoy.coverage_role = _prefer_inventory_value(normalized["coverage_role"], decoy.coverage_role, "internet_edge")
        decoy.environment = _prefer_inventory_value(normalized["environment"], decoy.environment, "unknown")
        decoy.site = _prefer_inventory_value(normalized["site"], decoy.site, "unknown")
        decoy.last_seen_at = utcnow()

    normalized["coverage_role"] = _prefer_inventory_value(normalized["coverage_role"], decoy.coverage_role, "internet_edge")
    normalized["environment"] = _prefer_inventory_value(normalized["environment"], decoy.environment, "unknown")
    normalized["site"] = _prefer_inventory_value(normalized["site"], decoy.site, "unknown")

    deployment = db.query(Deployment).filter(Deployment.decoy_id == decoy.id if decoy.id else False).order_by(Deployment.updated_at.desc()).first()
    if deployment is None:
        deployment = Deployment(
            decoy=decoy,
            edge_node_id=normalized["edge_node_id"],
            profile=normalized["profile"],
            build_version=normalized["decoy_version"],
            public_endpoint=normalized["public_endpoint"],
            runtime="unikraft-kvm",
            status="active",
            desired_state="running",
            observed_state="running",
            runtime_state="running",
            site=normalized["site"],
            environment=normalized["environment"],
            coverage_role=normalized["coverage_role"],
            metadata_json={"collector_version": normalized["collector_version"]},
        )
        db.add(deployment)
    else:
        deployment.edge_node_id = normalized["edge_node_id"]
        deployment.profile = normalized["profile"]
        deployment.build_version = normalized["decoy_version"]
        deployment.public_endpoint = normalized["public_endpoint"] or deployment.public_endpoint
        deployment.status = "active"
        deployment.desired_state = "running"
        deployment.observed_state = "running"
        deployment.runtime_state = "running"
        deployment.site = normalized["site"]
        deployment.environment = normalized["environment"]
        deployment.coverage_role = normalized["coverage_role"]
        deployment.metadata_json = {**(deployment.metadata_json or {}), "collector_version": normalized["collector_version"]}
    db.flush()
    return decoy


def insert_event(db: Session, payload: IngestEventIn) -> Event:
    reconcile_expected_fleet(db)
    normalized = normalize_payload(payload)
    existing = db.query(Event).filter(Event.event_id == normalized["event_id"]).one_or_none()
    if existing is not None:
        return existing

    decoy = upsert_decoy(db, normalized)
    event = Event(
        event_id=normalized["event_id"],
        occurred_at=normalized["occurred_at"],
        decoy=decoy,
        decoy_id=normalized["decoy_id"],
        profile=normalized["profile"],
        edge_node_id=normalized["edge_node_id"],
        decoy_version=normalized["decoy_version"],
        collector_version=normalized["collector_version"],
        site=normalized["site"],
        environment=normalized["environment"],
        coverage_role=normalized["coverage_role"],
        src_ip=normalized["src_ip"],
        source_country=normalized["source_country"],
        method=normalized["method"],
        path=normalized["path"],
        request_fingerprint=normalized["request_fingerprint"],
        event_class=normalized["event_class"],
        status_code=normalized["status_code"],
        user_agent=normalized["user_agent"],
        username=normalized["username"],
        password=normalized["password"],
        suspicious=normalized["suspicious"],
        latency_ms=normalized["latency_ms"],
        tags=normalized["tags"],
        normalized_tags=normalized["normalized_tags"],
        headers_subset=normalized["headers_subset"],
        raw_json=normalized["raw_json"],
    )
    db.add(event)
    db.flush()

    if normalized["username"] or normalized["password"]:
        db.add(
            CredentialAttempt(
                event_pk=event.id,
                decoy_id=normalized["decoy_id"],
                src_ip=normalized["src_ip"],
                username=normalized["username"],
                password=normalized["password"],
                attempted_at=normalized["occurred_at"],
            )
        )

    return event


def upsert_heartbeat(db: Session, payload: HeartbeatIn) -> Decoy:
    reconcile_expected_fleet(db)
    ts = payload.ts if isinstance(payload.ts, datetime) else utcnow()
    decoy = db.query(Decoy).filter(Decoy.decoy_id == payload.decoy_id).one_or_none()
    if decoy is None:
        decoy = Decoy(
            decoy_id=payload.decoy_id,
            profile=payload.profile,
            edge_node_id=payload.edge_node_id,
            decoy_version=payload.decoy_version,
            collector_version=payload.collector_version or settings.collector_version,
            public_endpoint=payload.public_endpoint,
            status="active",
            health_status="healthy",
            coverage_role=payload.coverage_role,
            environment=payload.environment,
            site=payload.site,
            last_seen_at=ts,
            last_heartbeat_at=ts,
        )
        db.add(decoy)
        db.flush()
    else:
        decoy.profile = payload.profile
        decoy.edge_node_id = payload.edge_node_id
        decoy.decoy_version = payload.decoy_version
        decoy.collector_version = payload.collector_version or decoy.collector_version
        decoy.public_endpoint = payload.public_endpoint or decoy.public_endpoint
        decoy.status = "active"
        decoy.health_status = "healthy"
        decoy.coverage_role = payload.coverage_role
        decoy.environment = payload.environment
        decoy.site = payload.site
        decoy.last_seen_at = ts
        decoy.last_heartbeat_at = ts

    deployment = db.query(Deployment).filter(Deployment.decoy_id == decoy.id).order_by(Deployment.updated_at.desc()).first()
    if deployment is None:
        deployment = Deployment(
            decoy=decoy,
            edge_node_id=payload.edge_node_id,
            profile=payload.profile,
            runtime="unikraft-kvm",
            build_version=payload.decoy_version,
            public_endpoint=payload.public_endpoint,
            status="active",
            desired_state="running",
            observed_state="running",
            runtime_state=payload.runtime_state,
            site=payload.site,
            environment=payload.environment,
            coverage_role=payload.coverage_role,
            metadata_json={"relay_health": payload.relay_health, "relay_queue_backlog": payload.relay_queue_backlog},
        )
        db.add(deployment)
    else:
        deployment.edge_node_id = payload.edge_node_id
        deployment.profile = payload.profile
        deployment.build_version = payload.decoy_version
        deployment.public_endpoint = payload.public_endpoint or deployment.public_endpoint
        deployment.status = "active"
        deployment.desired_state = "running"
        deployment.observed_state = "running"
        deployment.runtime_state = payload.runtime_state
        deployment.site = payload.site
        deployment.environment = payload.environment
        deployment.coverage_role = payload.coverage_role
        deployment.metadata_json = {
            **(deployment.metadata_json or {}),
            "relay_health": payload.relay_health,
            "relay_queue_backlog": payload.relay_queue_backlog,
            "uptime_seconds": payload.uptime_seconds,
            "listen_port": payload.listen_port,
        }
    db.flush()
    return decoy


def _recent_events_for_source(db: Session, event: Event, window_minutes: int) -> list[Event]:
    cutoff = event.occurred_at - timedelta(minutes=window_minutes)
    return (
        db.query(Event)
        .filter(Event.src_ip == event.src_ip, Event.occurred_at >= cutoff, Event.occurred_at <= event.occurred_at)
        .order_by(Event.occurred_at.asc())
        .all()
    )


def _ensure_investigation(db: Session, fingerprint: str, event: Event) -> Investigation:
    investigation = db.query(Investigation).filter(Investigation.fingerprint == fingerprint).one_or_none()
    if investigation is None:
        investigation = Investigation(
            fingerprint=fingerprint,
            first_seen=event.occurred_at,
            last_seen=event.occurred_at,
            detection_count=0,
            decoy_spread=1,
            activity_class="unknown",
        )
        db.add(investigation)
        db.flush()
    else:
        investigation.last_seen = max(investigation.last_seen, event.occurred_at)
    return investigation


def _update_investigation_stats(db: Session, investigation: Investigation) -> None:
    detections = db.query(Detection).filter(Detection.investigation_id == investigation.id).all()
    investigation.detection_count = len(detections)
    spread = len({d.decoy_id for d in detections if d.decoy_id})
    investigation.decoy_spread = max(spread, 1 if detections else 0)
    if investigation.decoy_spread >= 3 and investigation.detection_count >= 3:
        investigation.activity_class = "targeted"
    elif investigation.decoy_spread >= 2:
        investigation.activity_class = "opportunistic"
    else:
        investigation.activity_class = "unknown"


def _record_detection(
    db: Session,
    *,
    event: Event,
    detection_type: str,
    title: str,
    summary: str,
    fingerprint: str,
    evidence: dict[str, Any],
) -> None:
    rule = DETECTION_RULES[detection_type]
    investigation = _ensure_investigation(db, event.src_ip or event.request_fingerprint, event)
    detection = db.query(Detection).filter(Detection.fingerprint == fingerprint).one_or_none()
    if detection is None:
        detection = Detection(
            fingerprint=fingerprint,
            detection_type=detection_type,
            severity=rule["severity"],
            confidence=rule["confidence"],
            status="new",
            title=title,
            summary=summary,
            recommended_action=rule["action"],
            recommended_block_targets=[event.src_ip] if event.src_ip and event.src_ip != "unknown" else [],
            evidence_summary=evidence,
            decoy=event.decoy,
            decoy_id=event.decoy_id,
            site=event.site,
            src_ip=event.src_ip,
            event=event,
            investigation=investigation,
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
        )
        db.add(detection)
    else:
        detection.occurrences += 1
        detection.last_seen_at = event.occurred_at
        detection.evidence_summary = {**(detection.evidence_summary or {}), **evidence}
        if event.src_ip and event.src_ip not in detection.recommended_block_targets:
            detection.recommended_block_targets = [*detection.recommended_block_targets, event.src_ip]
        if detection.investigation is None:
            detection.investigation = investigation
    db.flush()
    _update_investigation_stats(db, investigation)


def materialize_detections(db: Session, limit: int = 500) -> int:
    reconcile_expected_fleet(db)
    refresh_fleet_health(db)
    pending_events = (
        db.query(Event)
        .filter(Event.alert_processed.is_(False))
        .order_by(Event.occurred_at.asc())
        .limit(limit)
        .all()
    )
    if not pending_events:
        return 0

    processed = 0
    for event in pending_events:
        recent = _recent_events_for_source(db, event, settings.detection_window_minutes)
        usernames = {row.username for row in recent if row.username}
        decoys_hit = {row.decoy_id for row in _recent_events_for_source(db, event, settings.distributed_window_minutes)}
        unique_paths = {row.path for row in recent}
        types_to_emit: list[tuple[str, str, str, dict[str, Any]]] = []

        if "path_traversal_probe" in event.normalized_tags:
            types_to_emit.append(("path_traversal_probe", "Path Traversal Probe", "Traversal-like input observed.", {"paths": [event.path], "event_id": event.event_id}))
        if "xss_probe" in event.normalized_tags:
            types_to_emit.append(("xss_probe", "XSS Probe", "Script injection payload observed against decoy.", {"event_id": event.event_id}))
        if "sqli_probe" in event.normalized_tags:
            types_to_emit.append(("sqli_probe", "SQLi Probe", "SQL-like input observed in decoy interaction.", {"event_id": event.event_id}))
        if event.path in SENSITIVE_PATHS:
            types_to_emit.append(("sensitive_path_discovery", "Sensitive Path Discovery", "Sensitive administrative or secret path was requested.", {"path": event.path}))
        if len(unique_paths & SENSITIVE_PATHS) >= 2:
            types_to_emit.append(("admin_panel_enumeration", "Admin Panel Enumeration", "Repeated admin-adjacent paths were requested.", {"paths": sorted(unique_paths & SENSITIVE_PATHS)}))
        if event.path == "/login" and event.method == "POST" and len(recent) >= 3:
            types_to_emit.append(("credential_bruteforce", "Credential Brute Force", "Repeated login failures from a single source were observed.", {"attempts": len(recent), "usernames": sorted(usernames)}))
        if event.path == "/login" and event.method == "POST" and len(recent) >= 5 and len(usernames) >= 3:
            types_to_emit.append(("credential_stuffing", "Credential Stuffing", "The same source attempted multiple credentials across the login surface.", {"attempts": len(recent), "usernames": sorted(usernames)}))
        if len(unique_paths) >= 4 or (event.suspicious and event.event_class in {"recon", "scan"}):
            types_to_emit.append(("internet_recon", "Internet Reconnaissance", "Reconnaissance-like path discovery pattern observed.", {"paths": sorted(unique_paths)}))
        if len(decoys_hit) >= 3:
            types_to_emit.append(("distributed_scanner_activity", "Distributed Scanner Activity", "The same source touched multiple decoys within the observation window.", {"decoys": sorted(decoys_hit)}))

        seen_types: set[str] = set()
        for detection_type, title, summary, evidence in types_to_emit:
            if detection_type in seen_types:
                continue
            seen_types.add(detection_type)
            scope = event.src_ip if detection_type == "distributed_scanner_activity" else f"{event.src_ip}:{event.decoy_id}:{event.request_fingerprint}"
            fingerprint = f"{detection_type}:{scope}"
            _record_detection(
                db,
                event=event,
                detection_type=detection_type,
                title=title,
                summary=summary,
                fingerprint=fingerprint,
                evidence=evidence,
            )

        event.alert_processed = True
        processed += 1

    db.flush()
    return processed


def materialize_alerts(db: Session, limit: int = 500) -> int:
    return materialize_detections(db, limit=limit)


def query_fleet(db: Session) -> list[Decoy]:
    reconcile_expected_fleet(db)
    refresh_fleet_health(db)
    db.flush()
    return db.query(Decoy).order_by(Decoy.health_status.asc(), Decoy.site.asc(), Decoy.decoy_id.asc()).all()


def query_posture(db: Session) -> dict[str, Any]:
    reconcile_expected_fleet(db)
    refresh_fleet_health(db)
    recent_cutoff = utcnow() - timedelta(hours=24)
    detections = db.query(Detection).all()
    fleet = db.query(Decoy).all()

    recommended_blocks = sorted({
        target
        for detection in detections
        if detection.status in {"new", "triaging", "confirmed"}
        for target in detection.recommended_block_targets
    })
    coverage_gaps = sorted({decoy.site for decoy in fleet if decoy.health_status == "silent"})
    top_sources = [
        {"src_ip": src_ip, "hits": hits}
        for src_ip, hits in (
            db.query(Event.src_ip, func.count(Event.id).label("hits"))
            .group_by(Event.src_ip)
            .order_by(func.count(Event.id).desc(), Event.src_ip.asc())
            .limit(6)
            .all()
        )
    ]
    recent_detections = db.query(Detection).order_by(Detection.last_seen_at.desc()).limit(8).all()
    return {
        "detections_new": sum(1 for detection in detections if detection.status == "new"),
        "detections_in_triage": sum(1 for detection in detections if detection.status == "triaging"),
        "fleet_total": len(fleet),
        "fleet_unhealthy": sum(1 for decoy in fleet if decoy.health_status in {"degraded", "silent"}),
        "coverage_gaps": coverage_gaps,
        "recommended_blocks": recommended_blocks,
        "exposed_endpoints": sum(1 for decoy in fleet if bool(decoy.public_endpoint)),
        "critical_detections": sum(1 for detection in detections if detection.severity == "critical" and detection.status != "closed"),
        "high_detections": sum(1 for detection in detections if detection.severity == "high" and detection.status != "closed"),
        "medium_detections": sum(1 for detection in detections if detection.severity == "medium" and detection.status != "closed"),
        "active_decoys": sum(1 for decoy in fleet if decoy.health_status == "healthy"),
        "silent_decoys": sum(1 for decoy in fleet if decoy.health_status == "silent"),
        "degraded_decoys": sum(1 for decoy in fleet if decoy.health_status == "degraded"),
        "changes_last_24h": {
            "events": db.query(func.count(Event.id)).filter(Event.occurred_at >= recent_cutoff).scalar() or 0,
            "detections": db.query(func.count(Detection.id)).filter(Detection.last_seen_at >= recent_cutoff).scalar() or 0,
            "credentials": db.query(func.count(CredentialAttempt.id)).filter(CredentialAttempt.attempted_at >= recent_cutoff).scalar() or 0,
        },
        "top_sources": top_sources,
        "recent_detections": recent_detections,
    }


def query_overview(db: Session) -> dict[str, Any]:
    posture = query_posture(db)
    total_events = db.query(func.count(Event.id)).scalar() or 0
    suspicious_events = db.query(func.count(Event.id)).filter(Event.suspicious.is_(True)).scalar() or 0
    credential_attempts = db.query(func.count(CredentialAttempt.id)).scalar() or 0
    top_paths = [
        {"path": path, "hits": hits}
        for path, hits in (
            db.query(Event.path, func.count(Event.id).label("hits"))
            .group_by(Event.path)
            .order_by(func.count(Event.id).desc(), Event.path.asc())
            .limit(8)
            .all()
        )
    ]
    events_by_decoy = [
        {"decoy_id": decoy_id, "profile": profile, "hits": hits}
        for decoy_id, profile, hits in (
            db.query(Event.decoy_id, Event.profile, func.count(Event.id).label("hits"))
            .group_by(Event.decoy_id, Event.profile)
            .order_by(func.count(Event.id).desc(), Event.decoy_id.asc())
            .all()
        )
    ]
    return {
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "open_alerts": posture["detections_new"] + posture["detections_in_triage"],
        "unique_ips": db.query(func.count(func.distinct(Event.src_ip))).scalar() or 0,
        "credential_attempts": credential_attempts,
        "active_decoys": posture["active_decoys"],
        "top_paths": top_paths,
        "top_attackers": posture["top_sources"],
        "events_by_decoy": events_by_decoy,
        "recent_alerts": posture["recent_detections"],
    }


def list_block_targets(db: Session) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for detection in db.query(Detection).filter(Detection.status.in_(["new", "triaging", "confirmed"])).all():
        for target in detection.recommended_block_targets:
            if target:
                counter[target] += 1
    return [{"target": target, "detections": count} for target, count in counter.most_common()]


def _artifact_key(artifact_type: str, export_format: str) -> str:
    return f"{artifact_type}/{utcnow().strftime('%Y/%m/%d')}/{uuid.uuid4()}.{export_format}"


def create_artifact_record(
    db: Session,
    *,
    artifact_type: str,
    export_format: str,
    generated_by: str,
    body: bytes,
    content_type: str,
    linked_investigation: uuid.UUID | None = None,
) -> Artifact:
    bucket, object_key = put_bytes(_artifact_key(artifact_type, export_format), body, content_type)
    artifact = Artifact(
        artifact_type=artifact_type,
        export_format=export_format,
        generated_by=generated_by,
        bucket=bucket,
        object_key=object_key,
        linked_investigation=linked_investigation,
    )
    db.add(artifact)
    db.flush()
    return artifact


def build_blocklist_export(db: Session, request: BlocklistExportRequest, generated_by: str) -> Artifact:
    rows = list_block_targets(db)
    if request.format == "json":
        body = json.dumps({"generated_at": utcnow().isoformat(), "entries": rows}, indent=2).encode("utf-8")
        return create_artifact_record(
            db,
            artifact_type="blocklist",
            export_format="json",
            generated_by=generated_by,
            body=body,
            content_type="application/json",
        )

    lines = ["target,detections"]
    lines.extend(f"{row['target']},{row['detections']}" for row in rows)
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return create_artifact_record(
        db,
        artifact_type="blocklist",
        export_format="csv",
        generated_by=generated_by,
        body=body,
        content_type="text/csv",
    )


def build_evidence_export(db: Session, request: EvidenceExportRequest, generated_by: str) -> Artifact:
    linked_investigation: uuid.UUID | None = None
    payload: dict[str, Any]
    if request.investigation_id is not None:
        investigation = db.query(Investigation).filter(Investigation.id == request.investigation_id).one()
        linked_investigation = investigation.id
        detections = db.query(Detection).filter(Detection.investigation_id == investigation.id).all()
        payload = {
            "investigation": investigation.fingerprint,
            "status": investigation.status,
            "detections": [
                {
                    "type": detection.detection_type,
                    "title": detection.title,
                    "status": detection.status,
                    "recommended_action": detection.recommended_action,
                    "recommended_block_targets": detection.recommended_block_targets,
                }
                for detection in detections
            ],
        }
    else:
        detection = db.query(Detection).filter(Detection.id == request.detection_id).one()
        linked_investigation = detection.investigation_id
        payload = {
            "detection": detection.detection_type,
            "title": detection.title,
            "status": detection.status,
            "severity": detection.severity,
            "confidence": detection.confidence,
            "summary": detection.summary,
            "recommended_action": detection.recommended_action,
            "recommended_block_targets": detection.recommended_block_targets,
            "evidence_summary": detection.evidence_summary,
        }

    if request.format == "html":
        title = payload.get("title") or payload.get("investigation") or "Evidence Package"
        html = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Evidence Package</title>"
            "<style>body{font-family:Segoe UI,sans-serif;background:#f5f1e8;color:#1f2328;padding:24px;}pre{white-space:pre-wrap;background:#fff;border:1px solid #ddd;padding:16px;border-radius:12px;}</style>"
            f"</head><body><h1>{title}</h1><pre>{json.dumps(payload, indent=2)}</pre></body></html>"
        ).encode("utf-8")
        return create_artifact_record(
            db,
            artifact_type="evidence_package",
            export_format="html",
            generated_by=generated_by,
            body=html,
            content_type="text/html",
            linked_investigation=linked_investigation,
        )

    body = json.dumps(payload, indent=2).encode("utf-8")
    return create_artifact_record(
        db,
        artifact_type="evidence_package",
        export_format="json",
        generated_by=generated_by,
        body=body,
        content_type="application/json",
        linked_investigation=linked_investigation,
    )


def build_management_summary_export(db: Session, generated_by: str) -> Artifact:
    posture = query_posture(db)
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Management Summary</title>"
        "<style>body{font-family:Segoe UI,sans-serif;background:#f5f1e8;color:#1f2328;padding:24px;}section{background:#fff;border:1px solid #ddd;padding:18px;border-radius:16px;margin-bottom:16px;}ul{line-height:1.6;}</style>"
        "</head><body><h1>Management Summary</h1>"
        f"<section><h2>Detection posture</h2><ul><li>New detections: {posture['detections_new']}</li><li>In triage: {posture['detections_in_triage']}</li><li>Unhealthy fleet members: {posture['fleet_unhealthy']}</li><li>Coverage gaps: {', '.join(posture['coverage_gaps']) or 'none'}</li></ul></section>"
        f"<section><h2>Recommended blocks</h2><p>{', '.join(posture['recommended_blocks']) or 'No immediate block recommendations.'}</p></section>"
        "</body></html>"
    ).encode("utf-8")
    return create_artifact_record(
        db,
        artifact_type="management_summary",
        export_format="html",
        generated_by=generated_by,
        body=html,
        content_type="text/html",
    )
