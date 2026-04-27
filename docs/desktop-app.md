# Native Analyst App

The analyst console can run as a platform-independent native desktop app through Tauri. The desktop app packages the React SOC console and connects to the same self-hosted FastAPI control plane used by the browser UI.

## Architecture

The desktop app is intentionally a console only:

- It does not embed PostgreSQL, MinIO, KraftKit, or decoy VMs.
- It connects to the customer-controlled control plane over `VITE_API_BASE_URL`.
- In development, it defaults to `http://127.0.0.1:5000`.
- In production, point it at the private control-plane API behind authenticated ingress.

## Prerequisites

- Node.js 20 or newer
- Rust and Cargo from `https://rustup.rs`
- Windows WebView2 runtime on Windows
- Tauri platform prerequisites for macOS or Linux when building there

## Development

Start the control plane first:

```powershell
docker compose -f deploy/dev/docker-compose.yml up -d --build
```

Run the desktop shell:

```powershell
cd analyst-web
npm run tauri:dev
```

## Production Build

```powershell
cd analyst-web
npm run tauri:build
```

Build output is written under:

```text
analyst-web/src-tauri/target/release/bundle
```

## Configuration

For a non-local API, set the API base URL before building:

```powershell
$env:VITE_API_BASE_URL="https://honeynet.internal.example.com"
npm run tauri:build
```

For production/OIDC deployments, hide the development token entry:

```powershell
$env:VITE_HIDE_DEV_TOKEN_ENTRY="true"
npm run tauri:build
```
