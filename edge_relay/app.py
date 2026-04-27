from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

from fastapi import FastAPI, HTTPException


UPSTREAM_EVENTS_URL = os.environ.get("EDGE_RELAY_UPSTREAM_EVENTS_URL", "http://127.0.0.1:8000/api/v1/events")
UPSTREAM_HEARTBEATS_URL = os.environ.get("EDGE_RELAY_UPSTREAM_HEARTBEATS_URL", "http://127.0.0.1:8000/api/v1/heartbeats")
UPSTREAM_INGEST_KEY = os.environ.get("EDGE_RELAY_UPSTREAM_INGEST_KEY", "dev-ingest-key")
SPOOL_DIR = Path(os.environ.get("EDGE_RELAY_SPOOL_DIR", "/var/lib/honeynet-edge-relay"))
REPLAY_INTERVAL_SECONDS = int(os.environ.get("EDGE_RELAY_REPLAY_INTERVAL_SECONDS", "5"))
FORWARD_TIMEOUT_SECONDS = int(os.environ.get("EDGE_RELAY_TIMEOUT_SECONDS", "3"))
MAX_SPOOL_LINES = int(os.environ.get("EDGE_RELAY_MAX_SPOOL_LINES", "2000"))

app = FastAPI(title="Honeynet Edge Relay", version="0.2.0")

_lock = threading.Lock()
_stats = {
    "events": {"forwarded": 0, "queued": 0, "replayed": 0, "failed": 0},
    "heartbeats": {"forwarded": 0, "queued": 0, "replayed": 0, "failed": 0},
}
_last_upstream_error = ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_spool_dir() -> None:
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)


def spool_path(kind: str) -> Path:
    ensure_spool_dir()
    return SPOOL_DIR / f"{kind}.jsonl"


def forward_payload(kind: str, payload: dict[str, Any]) -> None:
    global _last_upstream_error

    encoded = json.dumps(payload).encode("utf-8")
    target_url = UPSTREAM_EVENTS_URL if kind == "events" else UPSTREAM_HEARTBEATS_URL
    req = request.Request(
        target_url,
        data=encoded,
        headers={
            "Content-Type": "application/json",
            "X-Ingest-Key": UPSTREAM_INGEST_KEY,
        },
        method="POST",
    )
    with request.urlopen(req, timeout=FORWARD_TIMEOUT_SECONDS) as response:
        if response.status >= 400:
            _last_upstream_error = f"upstream returned {response.status}"
            raise RuntimeError(_last_upstream_error)
    _last_upstream_error = ""


def queue_payload(kind: str, payload: dict[str, Any]) -> None:
    path = spool_path(kind)
    with _lock:
        existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        existing.append(json.dumps(payload))
        if len(existing) > MAX_SPOOL_LINES:
            existing = existing[-MAX_SPOOL_LINES:]
        path.write_text("\n".join(existing) + ("\n" if existing else ""), encoding="utf-8")
        _stats[kind]["queued"] += 1


def drain_spool_once(kind: str) -> None:
    path = spool_path(kind)
    if not path.exists():
        return

    with _lock:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return
        path.write_text("", encoding="utf-8")

    failed: list[str] = []
    for line in lines:
        try:
            forward_payload(kind, json.loads(line))
            _stats[kind]["replayed"] += 1
        except Exception:  # noqa: BLE001
            failed.append(line)
            _stats[kind]["failed"] += 1

    if failed:
        with _lock:
            path.write_text("\n".join(failed) + "\n", encoding="utf-8")


def replay_loop() -> None:
    while True:
        for kind in ("events", "heartbeats"):
            try:
                drain_spool_once(kind)
            except Exception:  # noqa: BLE001
                _stats[kind]["failed"] += 1
        time.sleep(REPLAY_INTERVAL_SECONDS)


@app.on_event("startup")
def on_startup() -> None:
    ensure_spool_dir()
    threading.Thread(target=replay_loop, name="edge-relay-replay", daemon=True).start()


@app.get("/health")
def health() -> dict[str, Any]:
    event_lines = len(spool_path("events").read_text(encoding="utf-8").splitlines()) if spool_path("events").exists() else 0
    heartbeat_lines = len(spool_path("heartbeats").read_text(encoding="utf-8").splitlines()) if spool_path("heartbeats").exists() else 0
    relay_health = "degraded" if _last_upstream_error else "healthy"
    return {
        "status": "ok",
        "relay_health": relay_health,
        "ts": utc_now(),
        "upstream_events_url": UPSTREAM_EVENTS_URL,
        "upstream_heartbeats_url": UPSTREAM_HEARTBEATS_URL,
        "queued_lines": {"events": event_lines, "heartbeats": heartbeat_lines},
        "stats": _stats,
        "last_upstream_error": _last_upstream_error,
    }


def _handle_ingest(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="expected JSON object")

    payload.setdefault("edge_node_id", os.environ.get("EDGE_NODE_ID", "unknown-edge"))
    payload.setdefault("collector_version", "edge-relay/0.2.0")
    try:
        forward_payload(kind, payload)
        _stats[kind]["forwarded"] += 1
        return {"status": "forwarded"}
    except (error.URLError, TimeoutError, RuntimeError):
        queue_payload(kind, payload)
        return {"status": "queued"}


@app.post("/event")
def ingest_event(payload: dict[str, Any]) -> dict[str, Any]:
    return _handle_ingest("events", payload)


@app.post("/heartbeat")
def ingest_heartbeat(payload: dict[str, Any]) -> dict[str, Any]:
    return _handle_ingest("heartbeats", payload)
