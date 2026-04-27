import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["HONEYPOT_EXPECTED_FLEET_JSON"] = (
    '[{"decoy_id":"gw-core-01","profile":"router","site":"london-branch","environment":"dmz","coverage_role":"internet_edge","public_endpoint":"http://gw","host_port":8081,"edge_node_id":"edge-a"}]'
)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ingest_api.database import Base
from ingest_api.models import Artifact, CredentialAttempt, Decoy, Detection, Event
from ingest_api.schemas import BlocklistExportRequest, HeartbeatIn, IngestEventIn
from ingest_api.services import build_blocklist_export, insert_event, materialize_detections, query_posture, upsert_heartbeat


def build_session():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)()


def test_insert_event_backfills_defaults_and_expected_fleet():
    session = build_session()
    event = insert_event(
        session,
        IngestEventIn(
            decoy_id="gw-core-01",
            profile="router",
            src_ip="198.51.100.10",
            method="get",
            path="/login",
        ),
    )
    session.commit()

    stored = session.query(Event).filter_by(event_id=event.event_id).one()
    decoy = session.query(Decoy).filter_by(decoy_id="gw-core-01").one()

    assert stored.method == "GET"
    assert stored.edge_node_id == "unknown-edge"
    assert stored.status_code == 0
    assert stored.headers_subset == {}
    assert stored.request_fingerprint
    assert stored.event_class in {"probe", "credential", "recon", "scan"}
    assert decoy.site == "london-branch"


def test_upsert_heartbeat_sets_fleet_health():
    session = build_session()
    upsert_heartbeat(
        session,
        HeartbeatIn(
            decoy_id="gw-core-01",
            edge_node_id="edge-a",
            decoy_version="0.2.0",
            public_endpoint="http://gw",
            profile="router",
            uptime_seconds=120,
            listen_port=80,
            site="london-branch",
            environment="dmz",
            coverage_role="internet_edge",
        ),
    )
    session.commit()

    decoy = session.query(Decoy).filter_by(decoy_id="gw-core-01").one()
    assert decoy.health_status == "healthy"
    assert decoy.last_heartbeat_at is not None


def test_materialize_detections_creates_credential_and_distributed_findings():
    session = build_session()
    occurred_at = datetime.now(timezone.utc)

    for index, decoy_id in enumerate(["gw-core-01", "cam-admin-02", "ops-panel-03", "gw-core-01", "cam-admin-02"]):
        insert_event(
            session,
            IngestEventIn(
                event_id=f"evt-{index}",
                ts=occurred_at + timedelta(seconds=index),
                decoy_id=decoy_id,
                profile="router" if decoy_id == "gw-core-01" else "admin",
                src_ip="198.51.100.24",
                method="POST",
                path="/login",
                username=f"user-{index}",
                password=f"guess-{index}",
                site="london-branch",
                environment="dmz",
                coverage_role="internet_edge",
            ),
        )

    session.commit()
    processed = materialize_detections(session, limit=50)
    session.commit()

    detection_types = {row.detection_type for row in session.query(Detection).all()}
    credentials = session.query(CredentialAttempt).count()

    assert processed == 5
    assert credentials == 5
    assert "credential_stuffing" in detection_types
    assert "distributed_scanner_activity" in detection_types


def test_posture_reports_coverage_and_recommended_blocks():
    session = build_session()
    insert_event(
        session,
        IngestEventIn(
            decoy_id="gw-core-01",
            profile="router",
            src_ip="198.51.100.24",
            method="GET",
            path="/.env",
            suspicious=True,
            tags=["sensitive_path_discovery"],
            site="london-branch",
            environment="dmz",
            coverage_role="internet_edge",
        ),
    )
    session.commit()
    materialize_detections(session, limit=20)
    session.commit()

    posture = query_posture(session)

    assert posture["fleet_total"] >= 1
    assert "london-branch" in posture["coverage_gaps"] or posture["active_decoys"] >= 1
    assert "198.51.100.24" in posture["recommended_blocks"]


def test_blocklist_export_persists_artifact_metadata():
    session = build_session()
    insert_event(
        session,
        IngestEventIn(
            decoy_id="gw-core-01",
            profile="router",
            src_ip="198.51.100.24",
            method="GET",
            path="/admin",
            suspicious=True,
            tags=["admin_panel_enumeration"],
            site="london-branch",
            environment="dmz",
            coverage_role="internet_edge",
        ),
    )
    session.commit()
    materialize_detections(session, limit=20)
    session.commit()

    with patch("ingest_api.services.put_bytes", return_value=("test-bucket", "blocklist/test.csv")):
        artifact = build_blocklist_export(session, BlocklistExportRequest(format="csv"), "tester")
        session.commit()

    stored = session.query(Artifact).filter_by(id=artifact.id).one()
    assert stored.bucket == "test-bucket"
    assert stored.artifact_type == "blocklist"
