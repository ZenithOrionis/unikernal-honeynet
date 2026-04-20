from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT_DIR / "collector" / "events.db"
DEFAULT_OUTPUT = ROOT_DIR / "dashboard" / "output" / "report.html"


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_scalar(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> Any:
    row = conn.execute(query, params).fetchone()
    return row[0] if row else 0


def fetch_rows(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(query, params).fetchall()]


def load_summary(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")

    with get_connection(db_path) as conn:
        total_events = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events"))
        suspicious_events = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events WHERE suspicious = 1"))
        unique_ips = int(
            fetch_scalar(conn, "SELECT COUNT(DISTINCT src_ip) FROM events WHERE TRIM(src_ip) <> ''")
        )
        login_attempts = int(fetch_scalar(conn, "SELECT COUNT(*) FROM events WHERE path = '/login'"))
        by_decoy = fetch_rows(
            conn,
            """
            SELECT decoy_id, profile, COUNT(*) AS hits, SUM(suspicious) AS suspicious_hits
            FROM events
            GROUP BY decoy_id, profile
            ORDER BY hits DESC, decoy_id ASC
            """,
        )
        top_ips = fetch_rows(
            conn,
            """
            SELECT src_ip, COUNT(*) AS hits
            FROM events
            GROUP BY src_ip
            ORDER BY hits DESC, src_ip ASC
            LIMIT 10
            """,
        )
        top_paths = fetch_rows(
            conn,
            """
            SELECT path, COUNT(*) AS hits
            FROM events
            GROUP BY path
            ORDER BY hits DESC, path ASC
            LIMIT 10
            """,
        )
        suspicious_rows = fetch_rows(
            conn,
            """
            SELECT ts, decoy_id, src_ip, path, username, password, tags
            FROM events
            WHERE suspicious = 1
            ORDER BY id DESC
            LIMIT 20
            """,
        )
        login_rows = fetch_rows(
            conn,
            """
            SELECT ts, decoy_id, src_ip, username, password, user_agent
            FROM events
            WHERE path = '/login' AND method = 'POST'
            ORDER BY id DESC
            LIMIT 20
            """,
        )

    for row in suspicious_rows:
        try:
            row["tags"] = json.loads(row.get("tags") or "[]")
        except json.JSONDecodeError:
            row["tags"] = []

    return {
        "db_path": str(db_path),
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "unique_ips": unique_ips,
        "login_attempts": login_attempts,
        "by_decoy": by_decoy,
        "top_ips": top_ips,
        "top_paths": top_paths,
        "suspicious_rows": suspicious_rows,
        "login_rows": login_rows,
    }


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        rows = [["No data yet."] + [""] * (len(headers) - 1)]
    thead = "".join(f"<th>{header}</th>" for header in headers)
    body_rows = []
    for row in rows:
        body_rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    tbody = "".join(body_rows)
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>"


def render_html(summary: dict[str, Any]) -> str:
    by_decoy = render_table(
        ["Decoy", "Profile", "Hits", "Suspicious"],
        [
            [
                row["decoy_id"],
                row["profile"],
                str(row["hits"]),
                str(row.get("suspicious_hits") or 0),
            ]
            for row in summary["by_decoy"]
        ],
    )
    top_ips = render_table(
        ["Source IP", "Hits"],
        [[row["src_ip"], str(row["hits"])] for row in summary["top_ips"]],
    )
    top_paths = render_table(
        ["Path", "Hits"],
        [[row["path"], str(row["hits"])] for row in summary["top_paths"]],
    )
    suspicious = render_table(
        ["Timestamp", "Decoy", "Source", "Path", "Credentials", "Tags"],
        [
            [
                row["ts"],
                row["decoy_id"],
                row["src_ip"],
                row["path"],
                f"{row['username']} / {row['password']}".strip(" /"),
                ", ".join(row["tags"]),
            ]
            for row in summary["suspicious_rows"]
        ],
    )
    login_rows = render_table(
        ["Timestamp", "Decoy", "Source", "Username", "Password", "User-Agent"],
        [
            [
                row["ts"],
                row["decoy_id"],
                row["src_ip"],
                row["username"],
                row["password"],
                row["user_agent"],
            ]
            for row in summary["login_rows"]
        ],
    )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Unikernel Honeynet Report</title>
    <style>
      :root {{
        --bg: #f7f4eb;
        --card: #fffdf9;
        --ink: #1d241f;
        --muted: #59665f;
        --line: #d8d1c7;
        --accent: #184c8f;
        --alert: #8c2c16;
      }}

      * {{
        box-sizing: border-box;
      }}

      body {{
        margin: 0;
        font-family: Georgia, "Times New Roman", serif;
        background: linear-gradient(180deg, #faf8f1 0%, var(--bg) 100%);
        color: var(--ink);
      }}

      main {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 36px 20px 48px;
      }}

      header {{
        margin-bottom: 24px;
      }}

      h1, h2 {{
        margin: 0 0 10px;
      }}

      p {{
        color: var(--muted);
        line-height: 1.55;
      }}

      .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
        margin: 24px 0;
      }}

      .card, section {{
        background: var(--card);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 18px;
        box-shadow: 0 8px 20px rgba(29, 36, 31, 0.05);
      }}

      .card strong {{
        display: block;
        font-size: 2rem;
        margin-top: 6px;
      }}

      .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 16px;
        margin-top: 16px;
      }}

      table {{
        width: 100%;
        border-collapse: collapse;
      }}

      th, td {{
        border-bottom: 1px solid var(--line);
        padding: 10px 8px;
        text-align: left;
        vertical-align: top;
        font-size: 0.95rem;
      }}

      th {{
        color: var(--accent);
        font-weight: 700;
      }}

      .meta {{
        font-size: 0.92rem;
      }}

      .accent {{
        color: var(--accent);
      }}

      .alert {{
        color: var(--alert);
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1>Unikernel Honeynet Report</h1>
        <p class="meta">
          Generated from <span class="accent">{summary["db_path"]}</span>
        </p>
        <p>
          This report summarizes attack-like activity across the three unikernel decoys and any
          compatible baseline clients sending the same event schema to the collector.
        </p>
      </header>

      <div class="cards">
        <div class="card"><div>Total events</div><strong>{summary["total_events"]}</strong></div>
        <div class="card"><div>Suspicious events</div><strong class="alert">{summary["suspicious_events"]}</strong></div>
        <div class="card"><div>Unique source IPs</div><strong>{summary["unique_ips"]}</strong></div>
        <div class="card"><div>Login attempts</div><strong>{summary["login_attempts"]}</strong></div>
      </div>

      <div class="grid">
        <section>
          <h2>Requests by decoy</h2>
          {by_decoy}
        </section>
        <section>
          <h2>Top source IPs</h2>
          {top_ips}
        </section>
        <section>
          <h2>Top attacked paths</h2>
          {top_paths}
        </section>
      </div>

      <div class="grid">
        <section>
          <h2>Recent suspicious events</h2>
          {suspicious}
        </section>
        <section>
          <h2>Recent login attempts</h2>
          {login_rows}
        </section>
      </div>
    </main>
  </body>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an HTML report from honeynet events.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to the collector SQLite DB")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to write the HTML report",
    )
    args = parser.parse_args()

    summary = load_summary(args.db)
    html = render_html(summary)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")

    print(f"Report written to {args.output}")
    print(f"Total events: {summary['total_events']}")
    print(f"Suspicious events: {summary['suspicious_events']}")
    print(f"Unique IPs: {summary['unique_ips']}")
    print(f"Login attempts: {summary['login_attempts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

