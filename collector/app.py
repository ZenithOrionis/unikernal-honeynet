from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from bootstrap_deps import ensure_local_deps

ensure_local_deps(__file__)

from flask import Flask, jsonify, render_template, request


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("COLLECTOR_DB", BASE_DIR / "events.db"))
SCHEMA_PATH = BASE_DIR / "schema.sql"

app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with get_connection() as conn:
        conn.executescript(schema)


def coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def coerce_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(value).strip()]


def normalize_event(payload: dict[str, Any], source_ip: str) -> dict[str, Any]:
    tags = coerce_tags(payload.get("tags"))
    src_ip = str(payload.get("src_ip") or source_ip or "unknown").strip()
    normalized = {
        "ts": str(payload.get("ts") or utc_now()).strip(),
        "decoy_id": str(payload.get("decoy_id") or "unknown-decoy").strip(),
        "profile": str(payload.get("profile") or "unknown").strip(),
        "src_ip": src_ip or "unknown",
        "method": str(payload.get("method") or "GET").strip().upper(),
        "path": str(payload.get("path") or "/").strip() or "/",
        "user_agent": str(payload.get("user_agent") or "").strip(),
        "username": str(payload.get("username") or "").strip(),
        "password": str(payload.get("password") or "").strip(),
        "suspicious": coerce_bool(payload.get("suspicious")),
        "tags": tags,
        "raw_json": json.dumps(payload, sort_keys=True),
    }
    return normalized


def insert_event(event: dict[str, Any]) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO events (
                ts, decoy_id, profile, src_ip, method, path, user_agent,
                username, password, suspicious, tags, raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["ts"],
                event["decoy_id"],
                event["profile"],
                event["src_ip"],
                event["method"],
                event["path"],
                event["user_agent"],
                event["username"],
                event["password"],
                int(event["suspicious"]),
                json.dumps(event["tags"]),
                event["raw_json"],
            ),
        )
        return int(cursor.lastrowid)


def fetch_scalar(query: str, params: tuple[Any, ...] = ()) -> Any:
    with get_connection() as conn:
        row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


def fetch_rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def build_summary(limit: int = 15) -> dict[str, Any]:
    total_events = int(fetch_scalar("SELECT COUNT(*) FROM events"))
    suspicious_events = int(fetch_scalar("SELECT COUNT(*) FROM events WHERE suspicious = 1"))
    unique_ips = int(
        fetch_scalar("SELECT COUNT(DISTINCT src_ip) FROM events WHERE TRIM(src_ip) <> ''")
    )
    login_attempts = int(fetch_scalar("SELECT COUNT(*) FROM events WHERE path = '/login'"))

    by_decoy = fetch_rows(
        """
        SELECT decoy_id, profile, COUNT(*) AS hits, SUM(suspicious) AS suspicious_hits
        FROM events
        GROUP BY decoy_id, profile
        ORDER BY hits DESC, decoy_id ASC
        """
    )
    by_path = fetch_rows(
        """
        SELECT path, COUNT(*) AS hits
        FROM events
        GROUP BY path
        ORDER BY hits DESC, path ASC
        LIMIT 10
        """
    )
    top_ips = fetch_rows(
        """
        SELECT src_ip, COUNT(*) AS hits
        FROM events
        GROUP BY src_ip
        ORDER BY hits DESC, src_ip ASC
        LIMIT 10
        """
    )
    recent_suspicious = fetch_rows(
        """
        SELECT ts, decoy_id, profile, src_ip, path, username, password, tags
        FROM events
        WHERE suspicious = 1
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    recent_events = fetch_rows(
        """
        SELECT ts, decoy_id, profile, src_ip, method, path, username, password, suspicious, tags
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    for row in recent_suspicious + recent_events:
        try:
            row["tags"] = json.loads(row.get("tags") or "[]")
        except json.JSONDecodeError:
            row["tags"] = []

    return {
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "unique_ips": unique_ips,
        "login_attempts": login_attempts,
        "by_decoy": by_decoy,
        "by_path": by_path,
        "top_ips": top_ips,
        "recent_suspicious": recent_suspicious,
        "recent_events": recent_events,
        "db_path": str(DB_PATH),
    }


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("index.html", summary=build_summary())


@app.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({"status": "ok", "ts": utc_now(), "db_path": str(DB_PATH)})


@app.route("/stats", methods=["GET"])
def stats() -> Any:
    return jsonify(build_summary())


@app.route("/api/events", methods=["GET"])
def api_events() -> Any:
    try:
        limit = max(1, min(int(request.args.get("limit", "50")), 250))
    except ValueError:
        limit = 50
    rows = fetch_rows(
        """
        SELECT id, ts, decoy_id, profile, src_ip, method, path, user_agent,
               username, password, suspicious, tags
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    for row in rows:
        try:
            row["tags"] = json.loads(row.get("tags") or "[]")
        except json.JSONDecodeError:
            row["tags"] = []
    return jsonify({"events": rows, "count": len(rows)})


@app.route("/event", methods=["POST"])
def event() -> Any:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "expected JSON object"}), 400

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    source_ip = forwarded_for.split(",")[0].strip() or (request.remote_addr or "")
    normalized = normalize_event(payload, source_ip)
    event_id = insert_event(normalized)
    return jsonify({"status": "stored", "event_id": event_id})


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("COLLECTOR_PORT", "5000")), debug=False)
