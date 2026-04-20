from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from bootstrap_deps import ensure_local_deps

ensure_local_deps(__file__)

import requests
from flask import Flask, Response, request


app = Flask(__name__)

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://host.docker.internal:5000/event")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))

SUSPICIOUS_MARKERS = {
    "union select": "sqli_probe",
    "<script>": "xss_probe",
    "../": "traversal_probe",
    "wget": "command_probe",
    "curl": "command_probe",
    "cmd=": "command_probe",
    ".env": "secret_probe",
    "phpmyadmin": "phpmyadmin_probe",
}

PROFILES = {
    "router": {
        "title": "EdgeRouter X",
        "banner": "Core Gateway Console",
        "label": "WAN routing node",
    },
    "nvr": {
        "title": "SecureVision NVR",
        "banner": "Camera management portal",
        "label": "CCTV storage controller",
    },
    "admin": {
        "title": "Internal Control Panel",
        "banner": "Restricted operations panel",
        "label": "Enterprise operations portal",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def config() -> dict[str, str]:
    profile_name = os.environ.get("BASELINE_PROFILE", os.environ.get("DECOY_PROFILE", "router")).strip().lower()
    profile = PROFILES.get(profile_name, PROFILES["router"])
    return {
        "profile": profile_name,
        "decoy_id": os.environ.get("BASELINE_ID", os.environ.get("DECOY_ID", "docker-baseline-01")),
        "title": os.environ.get("BASELINE_TITLE", os.environ.get("DECOY_TITLE", profile["title"])),
        "hostname": os.environ.get("BASELINE_HOSTNAME", os.environ.get("DECOY_HOSTNAME", "docker-node-01")),
        "label": os.environ.get("BASELINE_LABEL", os.environ.get("DECOY_LABEL", profile["label"])),
        "banner": profile["banner"],
    }


def detect_suspicious(*chunks: str) -> tuple[bool, list[str]]:
    haystack = " ".join(chunk for chunk in chunks if chunk).lower()
    tags: list[str] = []
    for marker, tag in SUSPICIOUS_MARKERS.items():
        if marker in haystack and tag not in tags:
            tags.append(tag)
    return bool(tags), tags


def send_event(payload: dict[str, Any]) -> None:
    try:
        requests.post(COLLECTOR_URL, json=payload, timeout=2)
    except requests.RequestException:
        pass


def render_page(kind: str, cfg: dict[str, str], message: str = "") -> str:
    titles = {
        "root": f"{cfg['title']} :: {cfg['hostname']}",
        "login": f"{cfg['title']} Login",
        "admin": f"{cfg['title']} Admin",
        "config": f"{cfg['title']} Configuration",
        "status": f"{cfg['title']} Status",
    }
    heading = {
        "root": cfg["banner"],
        "login": "Authentication Required",
        "admin": "Administrative Console",
        "config": "Device Configuration",
        "status": "Health Overview",
    }
    body = {
        "root": f"<p>{cfg['label']} at <strong>{cfg['hostname']}</strong> is online.</p><p><a href='/login'>Open login</a></p>",
        "login": (
            "<form method='post' action='/login'>"
            "<label>Username <input type='text' name='username'></label><br><br>"
            "<label>Password <input type='password' name='password'></label><br><br>"
            "<button type='submit'>Sign in</button>"
            "</form>"
        ),
        "admin": "<p>Administrative mode is locked. Additional privileges are required.</p>",
        "config": "<p>Configuration export is disabled for this session.</p>",
        "status": "<p>Service state: nominal. Last sync: 07 seconds ago.</p>",
    }
    notice = f"<p style='color:#8f2d1f;'><strong>{message}</strong></p>" if message else ""
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{titles[kind]}</title>
    <style>
      body {{
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        background: linear-gradient(180deg, #eef3f7, #dce6ee);
        color: #152129;
      }}
      main {{
        max-width: 520px;
        margin: 48px auto;
        background: #ffffff;
        border: 1px solid #ccd7e0;
        border-radius: 18px;
        padding: 28px;
        box-shadow: 0 12px 28px rgba(21, 33, 41, 0.08);
      }}
      .meta {{
        color: #54646f;
        font-size: 0.95rem;
      }}
      a {{
        color: #0a5887;
      }}
      input {{
        width: 100%;
        padding: 10px 12px;
        margin-top: 6px;
        border-radius: 10px;
        border: 1px solid #c6d0d8;
      }}
      button {{
        background: #0a5887;
        color: #fff;
        border: 0;
        border-radius: 10px;
        padding: 10px 14px;
      }}
    </style>
  </head>
  <body>
    <main>
      <div class="meta">{cfg['profile']} profile :: {cfg['hostname']}</div>
      <h1>{heading[kind]}</h1>
      {notice}
      {body[kind]}
    </main>
  </body>
</html>"""


def build_event(method: str, path: str, username: str = "", password: str = "") -> dict[str, Any]:
    cfg = config()
    suspicious, tags = detect_suspicious(
        path,
        request.query_string.decode("utf-8", errors="ignore"),
        request.get_data(as_text=True),
        username,
        password,
    )
    if path == "/login" and method == "POST":
        tags.extend(tag for tag in ["login_attempt", "credential_guess"] if tag not in tags)
    if path in {"/admin", "/config", "/status"} and "panel_probe" not in tags:
        tags.append("panel_probe")
    if path not in {"/", "/login", "/admin", "/config", "/status"} and "unknown_path" not in tags:
        tags.append("unknown_path")

    return {
        "ts": utc_now(),
        "decoy_id": cfg["decoy_id"],
        "profile": cfg["profile"],
        "src_ip": request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
        "method": method,
        "path": path,
        "user_agent": request.headers.get("User-Agent", ""),
        "username": username,
        "password": password,
        "suspicious": suspicious or "unknown_path" in tags,
        "tags": tags,
    }


@app.route("/", methods=["GET"])
def root() -> Response:
    send_event(build_event("GET", "/"))
    return Response(render_page("root", config()), mimetype="text/html")


@app.route("/login", methods=["GET", "POST"])
def login() -> Response:
    cfg = config()
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        send_event(build_event("POST", "/login", username=username, password=password))
        return Response(
            render_page("login", cfg, message="Authentication failed. Audit trail has been updated."),
            status=401,
            mimetype="text/html",
        )

    send_event(build_event("GET", "/login"))
    return Response(render_page("login", cfg), mimetype="text/html")


@app.route("/admin", methods=["GET"])
def admin() -> Response:
    send_event(build_event("GET", "/admin"))
    return Response(render_page("admin", config()), status=403, mimetype="text/html")


@app.route("/config", methods=["GET"])
def config_page() -> Response:
    send_event(build_event("GET", "/config"))
    return Response(render_page("config", config()), status=403, mimetype="text/html")


@app.route("/status", methods=["GET"])
def status_page() -> Response:
    send_event(build_event("GET", "/status"))
    return Response(render_page("status", config()), mimetype="text/html")


@app.route("/<path:requested>", methods=["GET", "POST"])
def catch_all(requested: str) -> Response:
    path = f"/{requested}"
    username = request.form.get("username", "") if request.method == "POST" else ""
    password = request.form.get("password", "") if request.method == "POST" else ""
    send_event(build_event(request.method, path, username=username, password=password))
    return Response("<h1>404</h1><p>Resource not found.</p>", status=404, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False)
