from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib import error, request


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT_DIR / "collector" / "events.db"
DEFAULT_OUTPUT = ROOT_DIR / "dashboard" / "output" / "report.html"
DEFAULT_API_BASE = "http://127.0.0.1:5000"
DEFAULT_TOKEN = "dev-analyst-token"


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_scalar(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> Any:
    row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


def load_summary_from_sqlite(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")

    with get_connection(db_path) as conn:
        total_events = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events"))
        suspicious_events = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events WHERE suspicious = 1"))
        unique_ips = int(fetch_scalar(conn, "SELECT COUNT(DISTINCT src_ip) FROM events WHERE TRIM(src_ip) <> ''"))
        credential_attempts = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events WHERE path = '/login'"))

    return {
        "source": str(db_path),
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "unique_ips": unique_ips,
        "credential_attempts": credential_attempts,
    }


def fetch_api_json(api_base_url: str, token: str, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    encoded = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{api_base_url.rstrip('/')}{path}",
        data=encoded,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    with request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def download_api_export(api_base_url: str, token: str, path: str) -> bytes:
    req = request.Request(
        f"{api_base_url.rstrip('/')}{path}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with request.urlopen(req, timeout=20) as response:
        return response.read()


def choose_default_output(output: Path, fmt: str) -> Path:
    if output.suffix.lower() == f".{fmt}":
        return output
    return output.with_suffix(f".{fmt}")


def write_legacy_html(output: Path, summary: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Legacy Honeynet Report</title>
    <style>
      body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: #f6f2e7; color: #1b2220; }}
      main {{ max-width: 860px; margin: 0 auto; padding: 32px 18px 48px; }}
      .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
      .card {{ background: #fffdf8; border: 1px solid #ddd5c6; border-radius: 18px; padding: 18px; }}
      .card strong {{ display: block; font-size: 2rem; margin-top: 6px; }}
    </style>
  </head>
  <body>
    <main>
      <h1>Legacy Honeynet Report</h1>
      <p>Fallback report generated from {summary["source"]}</p>
      <div class="cards">
        <div class="card"><div>Total events</div><strong>{summary["total_events"]}</strong></div>
        <div class="card"><div>Suspicious events</div><strong>{summary["suspicious_events"]}</strong></div>
        <div class="card"><div>Unique IPs</div><strong>{summary["unique_ips"]}</strong></div>
        <div class="card"><div>Credential attempts</div><strong>{summary["credential_attempts"]}</strong></div>
      </div>
    </main>
  </body>
</html>""",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an analyst report from the honeynet control plane.")
    parser.add_argument("--api-base-url", default=DEFAULT_API_BASE, help="Base URL of the ingest API")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="Analyst bearer token for authenticated exports")
    parser.add_argument("--format", default="html", choices=("html", "csv"), help="Export format")
    parser.add_argument("--mode", choices=("api", "sqlite", "auto"), default="auto", help="Preferred report source")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite fallback database for legacy demo mode")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination report path")
    args = parser.parse_args()

    output = choose_default_output(args.output, args.format)

    if args.mode in {"api", "auto"}:
        try:
            posture = fetch_api_json(args.api_base_url, args.token, "/api/v1/stats/posture")
            artifact = fetch_api_json(
                args.api_base_url,
                args.token,
                "/api/v1/reports/export",
                method="POST",
                payload={"format": args.format, "limit": 500},
            )
            payload = download_api_export(args.api_base_url, args.token, artifact["download_url"])
            output.parent.mkdir(parents=True, exist_ok=True)
            if args.format == "csv":
                output.write_bytes(payload)
            else:
                output.write_text(payload.decode("utf-8"), encoding="utf-8")
            print(f"Report written to {output}")
            print(f"Source: {args.api_base_url}")
            print(f"Detections new: {posture['detections_new']}")
            print(f"Fleet unhealthy: {posture['fleet_unhealthy']}")
            print(f"Coverage gaps: {', '.join(posture['coverage_gaps']) or 'none'}")
            print(f"Recommended blocks: {len(posture['recommended_blocks'])}")
            return 0
        except (error.URLError, error.HTTPError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
            if args.mode == "api":
                raise SystemExit(f"API export failed: {exc}") from exc

    if args.format != "html":
        raise SystemExit("SQLite fallback only supports HTML output. Use --mode api for CSV exports.")

    summary = load_summary_from_sqlite(args.db)
    write_legacy_html(output, summary)
    print(f"Report written to {output}")
    print(f"Source: {summary['source']}")
    print(f"Total events: {summary['total_events']}")
    print(f"Suspicious events: {summary['suspicious_events']}")
    print(f"Unique IPs: {summary['unique_ips']}")
    print(f"Credential attempts: {summary['credential_attempts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
