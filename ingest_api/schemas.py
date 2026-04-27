from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


def parse_timestamp(value: str | datetime | None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class IngestEventIn(BaseModel):
    event_id: str | None = None
    ts: datetime | str | None = None
    decoy_id: str
    profile: str
    src_ip: str | None = None
    method: str = "GET"
    path: str = "/"
    user_agent: str = ""
    username: str = ""
    password: str = ""
    suspicious: bool = False
    tags: list[str] = Field(default_factory=list)
    normalized_tags: list[str] = Field(default_factory=list)
    collector_version: str | None = None
    edge_node_id: str | None = None
    decoy_version: str | None = None
    status_code: int | None = None
    latency_ms: int | None = None
    headers_subset: dict[str, Any] | None = None
    public_endpoint: str | None = None
    request_fingerprint: str | None = None
    source_country: str | None = None
    event_class: str | None = None
    site: str | None = None
    environment: str | None = None
    coverage_role: str | None = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("ts")
    @classmethod
    def normalize_ts(cls, value: str | datetime | None) -> datetime:
        return parse_timestamp(value)


class HeartbeatIn(BaseModel):
    ts: datetime | str | None = None
    decoy_id: str
    edge_node_id: str
    decoy_version: str
    public_endpoint: str | None = None
    profile: str
    uptime_seconds: int = 0
    listen_port: int = 80
    site: str = "unknown"
    environment: str = "unknown"
    coverage_role: str = "internet_edge"
    runtime_state: str = "running"
    relay_queue_backlog: int = 0
    relay_health: str = "healthy"
    collector_version: str | None = None

    @field_validator("ts")
    @classmethod
    def normalize_ts(cls, value: str | datetime | None) -> datetime:
        return parse_timestamp(value)


class EventOut(BaseModel):
    id: uuid.UUID
    event_id: str
    occurred_at: datetime
    decoy_id: str
    profile: str
    edge_node_id: str
    decoy_version: str
    collector_version: str
    site: str
    environment: str
    coverage_role: str
    src_ip: str
    source_country: str | None
    method: str
    path: str
    request_fingerprint: str
    event_class: str
    status_code: int
    user_agent: str
    username: str
    password: str
    suspicious: bool
    latency_ms: int
    tags: list[str]
    normalized_tags: list[str]
    headers_subset: dict[str, Any]


class CredentialOut(BaseModel):
    id: uuid.UUID
    attempted_at: datetime
    decoy_id: str
    src_ip: str
    username: str
    password: str
    event_id: str


class FleetOut(BaseModel):
    decoy_id: str
    profile: str
    edge_node_id: str
    decoy_version: str
    collector_version: str
    public_endpoint: str | None
    status: str
    health_status: str
    coverage_role: str
    environment: str
    site: str
    last_seen_at: datetime
    last_heartbeat_at: datetime | None
    runtime_state: str = "unknown"
    failure_reason: str | None = None
    relay_health: str | None = None
    relay_queue_backlog: int | None = None


class DetectionOut(BaseModel):
    id: uuid.UUID
    detection_type: str
    severity: str
    confidence: str
    status: str
    title: str
    summary: str
    recommended_action: str
    recommended_block_targets: list[str]
    assigned_to: str | None
    triage_notes: str | None
    evidence_summary: dict[str, Any]
    decoy_id: str | None
    site: str | None
    src_ip: str | None
    occurrences: int
    first_seen_at: datetime
    last_seen_at: datetime
    investigation_id: uuid.UUID | None


class DetectionUpdateIn(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    triage_notes: str | None = None


class InvestigationOut(BaseModel):
    id: uuid.UUID
    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    detection_count: int
    decoy_spread: int
    activity_class: str
    analyst_notes: str | None
    status: str


class ArtifactOut(BaseModel):
    id: uuid.UUID
    artifact_type: str
    export_format: str
    generated_by: str
    generated_at: datetime
    bucket: str
    object_key: str
    linked_investigation: uuid.UUID | None
    download_url: str


class PostureOut(BaseModel):
    detections_new: int
    detections_in_triage: int
    fleet_total: int
    fleet_unhealthy: int
    coverage_gaps: list[str]
    recommended_blocks: list[str]
    exposed_endpoints: int
    critical_detections: int
    high_detections: int
    medium_detections: int
    active_decoys: int
    silent_decoys: int
    degraded_decoys: int
    changes_last_24h: dict[str, int]
    top_sources: list[dict[str, Any]]
    recent_detections: list[DetectionOut]


class ExportRequest(BaseModel):
    format: str = "html"
    limit: int = 200

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"html", "csv"}:
            raise ValueError("format must be html or csv")
        return normalized


class EvidenceExportRequest(BaseModel):
    format: str = "json"
    detection_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"json", "html"}:
            raise ValueError("format must be json or html")
        return normalized


class BlocklistExportRequest(BaseModel):
    format: str = "csv"

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"csv", "json"}:
            raise ValueError("format must be csv or json")
        return normalized


def render_csv(rows: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "occurred_at",
            "decoy_id",
            "profile",
            "site",
            "src_ip",
            "method",
            "path",
            "status_code",
            "event_class",
            "username",
            "password",
            "suspicious",
            "tags",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "tags": ",".join(row.get("tags", []))})
    return output.getvalue()
