from __future__ import annotations

from html import escape
from typing import Any


def render_report_html(rows: list[dict[str, Any]], overview: dict[str, Any]) -> str:
    row_html = "".join(
        "<tr>"
        f"<td>{escape(str(row['occurred_at']))}</td>"
        f"<td>{escape(row['decoy_id'])}</td>"
        f"<td>{escape(row['src_ip'])}</td>"
        f"<td>{escape(row['method'])} {escape(row['path'])}</td>"
        f"<td>{row['status_code']}</td>"
        f"<td>{'Yes' if row['suspicious'] else 'No'}</td>"
        f"<td>{escape(', '.join(row.get('tags', [])))}</td>"
        "</tr>"
        for row in rows
    )
    if not row_html:
        row_html = "<tr><td colspan='7'>No events available.</td></tr>"

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Honeynet Report Export</title>
    <style>
      body {{
        margin: 0;
        font-family: 'Segoe UI', sans-serif;
        background: #f4f1e8;
        color: #1d2327;
      }}
      main {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 32px 18px 48px;
      }}
      .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 18px;
      }}
      .card, .panel {{
        background: #fffdf8;
        border: 1px solid #d7d0c3;
        border-radius: 18px;
        padding: 18px;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
      }}
      th, td {{
        padding: 10px 8px;
        border-bottom: 1px solid #e4ddd0;
        text-align: left;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>Honeynet Report Export</h1>
      <div class="cards">
        <div class="card"><div>Total events</div><strong>{overview['total_events']}</strong></div>
        <div class="card"><div>Suspicious</div><strong>{overview['suspicious_events']}</strong></div>
        <div class="card"><div>Open alerts</div><strong>{overview['open_alerts']}</strong></div>
        <div class="card"><div>Active decoys</div><strong>{overview['active_decoys']}</strong></div>
      </div>
      <section class="panel">
        <h2>Events</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Decoy</th>
              <th>Source</th>
              <th>Request</th>
              <th>Status</th>
              <th>Suspicious</th>
              <th>Tags</th>
            </tr>
          </thead>
          <tbody>{row_html}</tbody>
        </table>
      </section>
    </main>
  </body>
</html>"""

