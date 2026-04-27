# Enterprise Honeynet V2

Enterprise Honeynet V2 is a self-hosted hybrid deception platform for mid-market SOC teams. It places low-interaction Unikraft decoys on customer-controlled edge hosts, then turns attacker interaction into detections, investigations, blocklist artifacts, and management-ready exports inside a customer-owned control plane.

Core promise:

> Your decoys catch attackers before your perimeter does. The platform tells analysts what to block, what to escalate, and what to hand to incident response.

## What is in this repository

- `ingest_api/`: FastAPI control plane, PostgreSQL models, migrations, worker-driven detection materialization, OIDC/dev auth, and MinIO-backed exports
- `analyst-web/`: React analyst console with posture, detections, investigations, fleet, exports, and raw event drill-down
- `analyst-web/src-tauri/`: Tauri desktop shell for packaging the analyst console as a native Windows, macOS, or Linux app
- `edge_relay/`: edge-side forwarder with separate event and heartbeat queues plus spool replay
- `unikernel-decoy/`: low-interaction HTTP decoy runtime for Unikraft/KVM with fingerprints and periodic heartbeats
- `deploy/dev/`: Docker Compose stack for local enterprise-style validation
- `deploy/k8s/`: Helm chart for self-hosted Kubernetes deployments
- `deploy/edge/`: Ansible and systemd assets for decoy and relay deployment on customer-controlled edge hosts
- `docs/`: buyer-facing and operator-facing product, architecture, deployment, and governance docs

## Architecture

```text
internet traffic
      |
 public edge IPs / NAT / load balancer
      |
  [Unikraft decoy fleet]
      |
 [edge relay + local queues]
      |
 private authenticated ingest
      |
 [FastAPI control plane] ---- [worker]
             |                   |
             +---- PostgreSQL ---+
             |
           [MinIO]
             |
      [React analyst console]
```

Trust boundary:
- No SaaS control plane
- PostgreSQL, MinIO, analyst UI, and API stay in the customer environment
- Edge decoys remain customer-controlled sensors

## Local quickstart

Start the local control plane:

```bash
docker compose -f deploy/dev/docker-compose.yml up --build
```

This brings up:
- PostgreSQL on `localhost:5432`
- MinIO on `localhost:9000` and console on `localhost:9001`
- FastAPI on `http://localhost:5000`
- Analyst UI on `http://localhost:5173`
- Worker in the same Compose network

Default dev credentials:
- Analyst token: `dev-analyst-token`
- Ingest key: `dev-ingest-key`
- MinIO: `minioadmin` / `minioadmin`

To make the three local decoys visible to other devices on the same LAN for `nmap` testing, see [docs/local-lan-exposure.md](C:/Users/Saphiya/Downloads/Unikernel/docs/local-lan-exposure.md). This exposes only ports `8081-8083`; keep the API, dashboard, database, and MinIO private.

## Primary analyst surfaces

- `Posture`: fleet health, severity load, recommended blocks, coverage gaps, and 24-hour change
- `Detections`: actionable findings with response recommendations and evidence export
- `Investigations`: grouped activity by source or campaign fingerprint
- `Fleet`: live sensor health, exposure, runtime state, and heartbeat freshness
- `Exports`: management summary, evidence packages, and IOC/blocklist artifacts
- `Events`: secondary drill-down for raw telemetry

## Native desktop app

The analyst console can also be packaged as a Tauri desktop app. The native app is a SOC console only; it still connects to the self-hosted control plane and does not embed PostgreSQL, MinIO, KraftKit, or decoy VMs.

```powershell
cd analyst-web
npm run tauri:dev
```

To build installers after installing Rust/Cargo:

```powershell
cd analyst-web
npm run tauri:build
```

See [docs/desktop-app.md](C:/Users/Saphiya/Downloads/Unikernel/docs/desktop-app.md).

## Production deployment model

- Decoys run on KVM-capable edge nodes using Unikraft and KraftKit
- The edge relay batches and replays both events and heartbeats
- The control plane runs in Kubernetes
- PostgreSQL is the system of record
- MinIO is the default self-hosted artifact store and remains S3-compatible

See:
- [docs/product-positioning.md](C:/Users/Saphiya/Downloads/Unikernel/docs/product-positioning.md)
- [docs/reference-architecture.md](C:/Users/Saphiya/Downloads/Unikernel/docs/reference-architecture.md)
- [docs/deployment-patterns.md](C:/Users/Saphiya/Downloads/Unikernel/docs/deployment-patterns.md)
- [docs/security-and-governance.md](C:/Users/Saphiya/Downloads/Unikernel/docs/security-and-governance.md)

## Validation

Recommended local validation:

```bash
py -3 -m compileall ingest_api edge_relay collector dashboard
py -3 -m pytest ingest_api\tests -q -p no:cacheprovider
cd analyst-web && npm run build && npm test -- --run
```

## Demo story

The strongest demo path is:

1. Launch the control plane
2. Run the edge decoys and relay
3. Generate scanner and credential activity
4. Show new detections
5. Pivot into an investigation
6. Export a blocklist artifact
7. Export a management summary

That flow demonstrates early warning, triage, containment guidance, and evidence handoff without leaving the platform.
