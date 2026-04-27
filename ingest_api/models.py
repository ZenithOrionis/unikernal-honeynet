from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ingest_api.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Decoy(Base):
    __tablename__ = "decoys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    decoy_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    profile: Mapped[str] = mapped_column(String(64), index=True)
    edge_node_id: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    decoy_version: Mapped[str] = mapped_column(String(64), default="unknown")
    collector_version: Mapped[str] = mapped_column(String(64), default="unknown")
    public_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    health_status: Mapped[str] = mapped_column(String(32), default="healthy", index=True)
    coverage_role: Mapped[str] = mapped_column(String(32), default="internet_edge", index=True)
    environment: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    site: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    events: Mapped[list["Event"]] = relationship(back_populates="decoy")
    deployments: Mapped[list["Deployment"]] = relationship(back_populates="decoy")
    detections: Mapped[list["Detection"]] = relationship(back_populates="decoy")


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    decoy_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("decoys.id"), nullable=True, index=True)
    edge_node_id: Mapped[str] = mapped_column(String(128), index=True)
    profile: Mapped[str] = mapped_column(String(64))
    runtime: Mapped[str] = mapped_column(String(64), default="unikraft-kvm")
    build_version: Mapped[str] = mapped_column(String(64), default="unknown")
    public_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    desired_state: Mapped[str] = mapped_column(String(32), default="running")
    observed_state: Mapped[str] = mapped_column(String(32), default="unknown")
    host_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    runtime_state: Mapped[str] = mapped_column(String(64), default="unknown")
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    site: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    environment: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    coverage_role: Mapped[str] = mapped_column(String(32), default="internet_edge", index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    launched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    decoy: Mapped[Decoy | None] = relationship(back_populates="deployments")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    decoy_pk: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("decoys.id"), nullable=True, index=True)
    decoy_id: Mapped[str] = mapped_column(String(128), index=True)
    profile: Mapped[str] = mapped_column(String(64), index=True)
    edge_node_id: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    decoy_version: Mapped[str] = mapped_column(String(64), default="unknown")
    collector_version: Mapped[str] = mapped_column(String(64), default="unknown")
    site: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    environment: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    coverage_role: Mapped[str] = mapped_column(String(32), default="internet_edge", index=True)
    src_ip: Mapped[str] = mapped_column(String(128), index=True)
    source_country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(255), index=True)
    request_fingerprint: Mapped[str] = mapped_column(String(128), index=True, default="unknown")
    event_class: Mapped[str] = mapped_column(String(32), default="probe", index=True)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    user_agent: Mapped[str] = mapped_column(Text, default="")
    username: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(String(255), default="")
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    normalized_tags: Mapped[list] = mapped_column(JSON, default=list)
    headers_subset: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_json: Mapped[dict] = mapped_column(JSON, default=dict)
    alert_processed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    decoy: Mapped[Decoy | None] = relationship(back_populates="events")
    credential: Mapped["CredentialAttempt | None"] = relationship(back_populates="event", uselist=False)
    detections: Mapped[list["Detection"]] = relationship(back_populates="event")


class CredentialAttempt(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_pk: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.id"), unique=True, index=True)
    decoy_id: Mapped[str] = mapped_column(String(128), index=True)
    src_ip: Mapped[str] = mapped_column(String(128), index=True)
    username: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(String(255), default="")
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    event: Mapped[Event] = relationship(back_populates="credential")


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_investigation_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(255), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    decoy_spread: Mapped[int] = mapped_column(Integer, default=1)
    activity_class: Mapped[str] = mapped_column(String(32), default="unknown")
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    detections: Mapped[list["Detection"]] = relationship(back_populates="investigation")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="investigation")


class Detection(Base):
    __tablename__ = "detections"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_detection_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(255), index=True)
    detection_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    confidence: Mapped[str] = mapped_column(String(32), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    recommended_block_targets: Mapped[list] = mapped_column(JSON, default=list)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    decoy_pk: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("decoys.id"), nullable=True)
    decoy_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    site: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    event_pk: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    decoy: Mapped[Decoy | None] = relationship(back_populates="detections")
    event: Mapped[Event | None] = relationship(back_populates="detections")
    investigation: Mapped[Investigation | None] = relationship(back_populates="detections")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    export_format: Mapped[str] = mapped_column(String(32))
    generated_by: Mapped[str] = mapped_column(String(255))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    bucket: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(String(512))
    linked_investigation: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)

    investigation: Mapped[Investigation | None] = relationship(back_populates="artifacts")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions: Mapped[list["Session"]] = relationship(back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_pk: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(64), default="oidc")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    user: Mapped[User] = relationship(back_populates="sessions")
