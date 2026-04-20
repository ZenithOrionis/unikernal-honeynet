from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from bootstrap_deps import ensure_local_deps

ensure_local_deps(__file__)

from flask import Flask, jsonify, render_template_string


DB_PATH = Path(os.environ.get("DASHBOARD_DB", ROOT_DIR / "collector" / "events.db"))

app = Flask(__name__)


HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Honeynet Dashboard</title>
    <style>
      :root {
        --bg: #eef4f1;
        --card: #ffffff;
        --ink: #1f2b25;
        --muted: #607168;
        --line: #d8e0da;
        --accent: #166b56;
        --warn: #9d4028;
      }

      body {
        margin: 0;
        font-family: "Trebuchet MS", "Segoe UI", sans-serif;
        background:
          radial-gradient(circle at top right, rgba(22, 107, 86, 0.12), transparent 28%),
          linear-gradient(180deg, #f7fbf8, var(--bg));
        color: var(--ink);
      }

      main {
        max-width: 1180px;
        margin: 0 auto;
        padding: 28px 18px 40px;
      }

      .row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 14px;
        margin-bottom: 18px;
      }

      .card, .panel {
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 18px;
        box-shadow: 0 10px 24px rgba(31, 43, 37, 0.05);
      }

      .card strong {
        display: block;
        font-size: 1.9rem;
        margin-top: 8px;
      }

      .panel-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 16px;
      }

      table {
        width: 100%;
        border-collapse: collapse;
      }

      th, td {
        padding: 10px 8px;
        text-align: left;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
      }

      th {
        color: var(--muted);
      }

      .badge {
        display: inline-block;
        margin: 2px 4px 2px 0;
        padding: 3px 9px;
        border-radius: 999px;
        background: #ddeee8;
        color: var(--accent);
        font-size: 0.8rem;
      }

      .danger {
        background: #f7e1dc;
        color: var(--warn);
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Live Honeynet Dashboard</h1>
      <p>Reading from <code>{{ db_path }}</code></p>

      <section class="row">
        <article class="card"><div>Total events</div><strong>{{ summary.total_events }}</strong></article>
        <article class="card"><div>Suspicious events</div><strong>{{ summary.suspicious_events }}</strong></article>
        <article class="card"><div>Unique IPs</div><strong>{{ summary.unique_ips }}</strong></article>
        <article class="card"><div>Login attempts</div><strong>{{ summary.login_attempts }}</strong></article>
      </section>

      <section class="panel-grid">
        <article class="panel">
          <h2>By decoy</h2>
          <table>
            <thead><tr><th>Decoy</th><th>Profile</th><th>Hits</th></tr></thead>
            <tbody>
              {% for row in summary.by_decoy %}
              <tr><td>{{ row.decoy_id }}</td><td>{{ row.profile }}</td><td>{{ row.hits }}</td></tr>
              {% else %}
              <tr><td colspan="3">No data yet.</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </article>

        <article class="panel">
          <h2>Top paths</h2>
          <table>
            <thead><tr><th>Path</th><th>Hits</th></tr></thead>
            <tbody>
              {% for row in summary.top_paths %}
              <tr><td>{{ row.path }}</td><td>{{ row.hits }}</td></tr>
              {% else %}
              <tr><td colspan="2">No data yet.</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </article>

        <article class="panel">
          <h2>Recent suspicious</h2>
          <table>
            <thead><tr><th>Time</th><th>Decoy</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in summary.recent_suspicious %}
              <tr>
                <td>{{ row.ts }}</td>
                <td>{{ row.decoy_id }}</td>
                <td>
                  <div>{{ row.src_ip }} -> {{ row.path }}</div>
                  <div>
                    {% for tag in row.tags %}
                    <span class="badge danger">{{ tag }}</span>
                    {% endfor %}
                  </div>
                </td>
              </tr>
              {% else %}
              <tr><td colspan="3">No suspicious events yet.</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </article>
      </section>
    </main>
  </body>
</html>"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_scalar(query: str, params: tuple[Any, ...] = ()) -> Any:
    with get_connection() as conn:
        row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


def fetch_rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def build_summary() -> dict[str, Any]:
    total_events = int(fetch_scalar("SELECT COUNT(*) FROM events"))
    suspicious_events = int(fetch_scalar("SELECT COUNT(*) FROM events WHERE suspicious = 1"))
    unique_ips = int(fetch_scalar("SELECT COUNT(DISTINCT src_ip) FROM events"))
    login_attempts = int(fetch_scalar("SELECT COUNT(*) FROM events WHERE path = '/login'"))
    by_decoy = fetch_rows(
        """
        SELECT decoy_id, profile, COUNT(*) AS hits
        FROM events
        GROUP BY decoy_id, profile
        ORDER BY hits DESC, decoy_id ASC
        """
    )
    top_paths = fetch_rows(
        """
        SELECT path, COUNT(*) AS hits
        FROM events
        GROUP BY path
        ORDER BY hits DESC, path ASC
        LIMIT 10
        """
    )
    recent_suspicious = fetch_rows(
        """
        SELECT ts, decoy_id, src_ip, path, tags
        FROM events
        WHERE suspicious = 1
        ORDER BY id DESC
        LIMIT 15
        """
    )
    for row in recent_suspicious:
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
        "top_paths": top_paths,
        "recent_suspicious": recent_suspicious,
    }


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template_string(HTML, summary=build_summary(), db_path=str(DB_PATH))


@app.route("/api/summary", methods=["GET"])
def api_summary() -> Any:
    return jsonify(build_summary())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("DASHBOARD_PORT", "8000")), debug=False)
