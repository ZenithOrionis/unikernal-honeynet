"""enterprise v2 schema

Revision ID: 0002_enterprise_v2
Revises: 0001_initial
Create Date: 2026-04-21
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_enterprise_v2"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("decoys", sa.Column("health_status", sa.String(length=32), nullable=False, server_default="healthy"))
    op.add_column("decoys", sa.Column("coverage_role", sa.String(length=32), nullable=False, server_default="internet_edge"))
    op.add_column("decoys", sa.Column("environment", sa.String(length=64), nullable=False, server_default="unknown"))
    op.add_column("decoys", sa.Column("site", sa.String(length=128), nullable=False, server_default="unknown"))
    op.add_column("decoys", sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_decoys_health_status", "decoys", ["health_status"])
    op.create_index("ix_decoys_coverage_role", "decoys", ["coverage_role"])
    op.create_index("ix_decoys_environment", "decoys", ["environment"])
    op.create_index("ix_decoys_site", "decoys", ["site"])
    op.create_index("ix_decoys_last_heartbeat_at", "decoys", ["last_heartbeat_at"])

    op.add_column("deployments", sa.Column("desired_state", sa.String(length=32), nullable=False, server_default="running"))
    op.add_column("deployments", sa.Column("observed_state", sa.String(length=32), nullable=False, server_default="unknown"))
    op.add_column("deployments", sa.Column("host_port", sa.Integer(), nullable=True))
    op.add_column("deployments", sa.Column("runtime_state", sa.String(length=64), nullable=False, server_default="unknown"))
    op.add_column("deployments", sa.Column("failure_reason", sa.Text(), nullable=True))
    op.add_column("deployments", sa.Column("site", sa.String(length=128), nullable=False, server_default="unknown"))
    op.add_column("deployments", sa.Column("environment", sa.String(length=64), nullable=False, server_default="unknown"))
    op.add_column("deployments", sa.Column("coverage_role", sa.String(length=32), nullable=False, server_default="internet_edge"))
    op.create_index("ix_deployments_site", "deployments", ["site"])
    op.create_index("ix_deployments_environment", "deployments", ["environment"])
    op.create_index("ix_deployments_coverage_role", "deployments", ["coverage_role"])

    op.add_column("events", sa.Column("site", sa.String(length=128), nullable=False, server_default="unknown"))
    op.add_column("events", sa.Column("environment", sa.String(length=64), nullable=False, server_default="unknown"))
    op.add_column("events", sa.Column("coverage_role", sa.String(length=32), nullable=False, server_default="internet_edge"))
    op.add_column("events", sa.Column("source_country", sa.String(length=64), nullable=True))
    op.add_column("events", sa.Column("request_fingerprint", sa.String(length=128), nullable=False, server_default="unknown"))
    op.add_column("events", sa.Column("event_class", sa.String(length=32), nullable=False, server_default="probe"))
    op.add_column("events", sa.Column("normalized_tags", sa.JSON(), nullable=False, server_default="[]"))
    op.create_index("ix_events_site", "events", ["site"])
    op.create_index("ix_events_environment", "events", ["environment"])
    op.create_index("ix_events_coverage_role", "events", ["coverage_role"])
    op.create_index("ix_events_request_fingerprint", "events", ["request_fingerprint"])
    op.create_index("ix_events_event_class", "events", ["event_class"])

    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("decoy_spread", sa.Integer(), nullable=False),
        sa.Column("activity_class", sa.String(length=32), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("fingerprint", name="uq_investigation_fingerprint"),
    )
    op.create_index("ix_investigations_fingerprint", "investigations", ["fingerprint"])
    op.create_index("ix_investigations_last_seen", "investigations", ["last_seen"])

    op.create_table(
        "detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("detection_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("recommended_block_targets", sa.JSON(), nullable=False),
        sa.Column("assigned_to", sa.String(length=255), nullable=True),
        sa.Column("triage_notes", sa.Text(), nullable=True),
        sa.Column("evidence_summary", sa.JSON(), nullable=False),
        sa.Column("decoy_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("decoys.id"), nullable=True),
        sa.Column("decoy_id", sa.String(length=128), nullable=True),
        sa.Column("site", sa.String(length=128), nullable=True),
        sa.Column("src_ip", sa.String(length=128), nullable=True),
        sa.Column("event_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("events.id"), nullable=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("investigations.id"), nullable=True),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("fingerprint", name="uq_detection_fingerprint"),
    )
    op.create_index("ix_detections_fingerprint", "detections", ["fingerprint"])
    op.create_index("ix_detections_type", "detections", ["detection_type"])
    op.create_index("ix_detections_status", "detections", ["status"])
    op.create_index("ix_detections_decoy_id", "detections", ["decoy_id"])
    op.create_index("ix_detections_site", "detections", ["site"])
    op.create_index("ix_detections_src_ip", "detections", ["src_ip"])
    op.create_index("ix_detections_last_seen_at", "detections", ["last_seen_at"])
    op.create_index("ix_detections_investigation_id", "detections", ["investigation_id"])

    op.create_table(
        "artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("export_format", sa.String(length=32), nullable=False),
        sa.Column("generated_by", sa.String(length=255), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket", sa.String(length=255), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("linked_investigation", postgresql.UUID(as_uuid=True), sa.ForeignKey("investigations.id"), nullable=True),
    )
    op.create_index("ix_artifacts_artifact_type", "artifacts", ["artifact_type"])
    op.create_index("ix_artifacts_generated_at", "artifacts", ["generated_at"])
    op.create_index("ix_artifacts_linked_investigation", "artifacts", ["linked_investigation"])


def downgrade() -> None:
    op.drop_index("ix_artifacts_linked_investigation", table_name="artifacts")
    op.drop_index("ix_artifacts_generated_at", table_name="artifacts")
    op.drop_index("ix_artifacts_artifact_type", table_name="artifacts")
    op.drop_table("artifacts")

    op.drop_index("ix_detections_investigation_id", table_name="detections")
    op.drop_index("ix_detections_last_seen_at", table_name="detections")
    op.drop_index("ix_detections_src_ip", table_name="detections")
    op.drop_index("ix_detections_site", table_name="detections")
    op.drop_index("ix_detections_decoy_id", table_name="detections")
    op.drop_index("ix_detections_status", table_name="detections")
    op.drop_index("ix_detections_type", table_name="detections")
    op.drop_index("ix_detections_fingerprint", table_name="detections")
    op.drop_table("detections")

    op.drop_index("ix_investigations_last_seen", table_name="investigations")
    op.drop_index("ix_investigations_fingerprint", table_name="investigations")
    op.drop_table("investigations")

    op.drop_index("ix_events_event_class", table_name="events")
    op.drop_index("ix_events_request_fingerprint", table_name="events")
    op.drop_index("ix_events_coverage_role", table_name="events")
    op.drop_index("ix_events_environment", table_name="events")
    op.drop_index("ix_events_site", table_name="events")
    op.drop_column("events", "normalized_tags")
    op.drop_column("events", "event_class")
    op.drop_column("events", "request_fingerprint")
    op.drop_column("events", "source_country")
    op.drop_column("events", "coverage_role")
    op.drop_column("events", "environment")
    op.drop_column("events", "site")

    op.drop_index("ix_deployments_coverage_role", table_name="deployments")
    op.drop_index("ix_deployments_environment", table_name="deployments")
    op.drop_index("ix_deployments_site", table_name="deployments")
    op.drop_column("deployments", "coverage_role")
    op.drop_column("deployments", "environment")
    op.drop_column("deployments", "site")
    op.drop_column("deployments", "failure_reason")
    op.drop_column("deployments", "runtime_state")
    op.drop_column("deployments", "host_port")
    op.drop_column("deployments", "observed_state")
    op.drop_column("deployments", "desired_state")

    op.drop_index("ix_decoys_last_heartbeat_at", table_name="decoys")
    op.drop_index("ix_decoys_site", table_name="decoys")
    op.drop_index("ix_decoys_environment", table_name="decoys")
    op.drop_index("ix_decoys_coverage_role", table_name="decoys")
    op.drop_index("ix_decoys_health_status", table_name="decoys")
    op.drop_column("decoys", "last_heartbeat_at")
    op.drop_column("decoys", "site")
    op.drop_column("decoys", "environment")
    op.drop_column("decoys", "coverage_role")
    op.drop_column("decoys", "health_status")
