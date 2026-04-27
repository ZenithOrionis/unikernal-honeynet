"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-20
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "decoys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("decoy_id", sa.String(length=128), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False),
        sa.Column("edge_node_id", sa.String(length=128), nullable=False),
        sa.Column("decoy_version", sa.String(length=64), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column("public_endpoint", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_decoys_decoy_id", "decoys", ["decoy_id"], unique=True)
    op.create_index("ix_decoys_profile", "decoys", ["profile"])
    op.create_index("ix_decoys_edge_node_id", "decoys", ["edge_node_id"])
    op.create_index("ix_decoys_last_seen_at", "decoys", ["last_seen_at"])

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_subject", "users", ["subject"], unique=True)
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "deployments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("decoy_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("decoys.id"), nullable=True),
        sa.Column("edge_node_id", sa.String(length=128), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False),
        sa.Column("runtime", sa.String(length=64), nullable=False),
        sa.Column("build_version", sa.String(length=64), nullable=False),
        sa.Column("public_endpoint", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("launched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_deployments_decoy_id", "deployments", ["decoy_id"])
    op.create_index("ix_deployments_edge_node_id", "deployments", ["edge_node_id"])

    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decoy_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("decoys.id"), nullable=True),
        sa.Column("decoy_id", sa.String(length=128), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False),
        sa.Column("edge_node_id", sa.String(length=128), nullable=False),
        sa.Column("decoy_version", sa.String(length=64), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column("src_ip", sa.String(length=128), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.String(length=255), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("password", sa.String(length=255), nullable=False),
        sa.Column("suspicious", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("headers_subset", sa.JSON(), nullable=False),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.Column("alert_processed", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_events_event_id", "events", ["event_id"], unique=True)
    op.create_index("ix_events_occurred_at", "events", ["occurred_at"])
    op.create_index("ix_events_received_at", "events", ["received_at"])
    op.create_index("ix_events_decoy_pk", "events", ["decoy_pk"])
    op.create_index("ix_events_decoy_id", "events", ["decoy_id"])
    op.create_index("ix_events_profile", "events", ["profile"])
    op.create_index("ix_events_edge_node_id", "events", ["edge_node_id"])
    op.create_index("ix_events_src_ip", "events", ["src_ip"])
    op.create_index("ix_events_path", "events", ["path"])
    op.create_index("ix_events_suspicious", "events", ["suspicious"])
    op.create_index("ix_events_alert_processed", "events", ["alert_processed"])

    op.create_table(
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("decoy_id", sa.String(length=128), nullable=False),
        sa.Column("src_ip", sa.String(length=128), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("password", sa.String(length=255), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_credentials_event_pk", "credentials", ["event_pk"], unique=True)
    op.create_index("ix_credentials_decoy_id", "credentials", ["decoy_id"])
    op.create_index("ix_credentials_src_ip", "credentials", ["src_ip"])
    op.create_index("ix_credentials_attempted_at", "credentials", ["attempted_at"])

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("decoy_id", sa.String(length=128), nullable=True),
        sa.Column("src_ip", sa.String(length=128), nullable=True),
        sa.Column("event_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("events.id"), nullable=True),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("fingerprint", name="uq_alert_fingerprint"),
    )
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])
    op.create_index("ix_alerts_type", "alerts", ["type"])
    op.create_index("ix_alerts_decoy_id", "alerts", ["decoy_id"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])

    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_pk", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_sessions_user_pk", "sessions", ["user_pk"])


def downgrade() -> None:
    op.drop_index("ix_sessions_user_pk", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_alerts_src_ip", table_name="alerts")
    op.drop_index("ix_alerts_decoy_id", table_name="alerts")
    op.drop_index("ix_alerts_type", table_name="alerts")
    op.drop_index("ix_alerts_fingerprint", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_credentials_attempted_at", table_name="credentials")
    op.drop_index("ix_credentials_src_ip", table_name="credentials")
    op.drop_index("ix_credentials_decoy_id", table_name="credentials")
    op.drop_index("ix_credentials_event_pk", table_name="credentials")
    op.drop_table("credentials")
    op.drop_index("ix_events_alert_processed", table_name="events")
    op.drop_index("ix_events_suspicious", table_name="events")
    op.drop_index("ix_events_path", table_name="events")
    op.drop_index("ix_events_src_ip", table_name="events")
    op.drop_index("ix_events_edge_node_id", table_name="events")
    op.drop_index("ix_events_profile", table_name="events")
    op.drop_index("ix_events_decoy_id", table_name="events")
    op.drop_index("ix_events_decoy_pk", table_name="events")
    op.drop_index("ix_events_received_at", table_name="events")
    op.drop_index("ix_events_occurred_at", table_name="events")
    op.drop_index("ix_events_event_id", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_deployments_edge_node_id", table_name="deployments")
    op.drop_index("ix_deployments_decoy_id", table_name="deployments")
    op.drop_table("deployments")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_subject", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_decoys_last_seen_at", table_name="decoys")
    op.drop_index("ix_decoys_edge_node_id", table_name="decoys")
    op.drop_index("ix_decoys_profile", table_name="decoys")
    op.drop_index("ix_decoys_decoy_id", table_name="decoys")
    op.drop_table("decoys")

