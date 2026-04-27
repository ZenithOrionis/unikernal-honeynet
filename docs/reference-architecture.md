# Reference Architecture

## Control plane

- FastAPI ingest and analyst API
- background worker for detection materialization and fleet posture refresh
- PostgreSQL as system of record
- MinIO for artifact storage
- React analyst UI

## Edge plane

- Unikraft decoys on KVM-capable hosts
- edge relay for event and heartbeat delivery
- systemd-managed decoy services

## Data flows

1. Decoy receives attacker traffic
2. Decoy emits request event and periodic heartbeat
3. Relay forwards to control plane or spools locally during outage
4. API stores telemetry in PostgreSQL
5. Worker creates detections and investigations
6. Analyst UI renders posture, detections, fleet, and exports
7. Exports are stored in MinIO and recorded in PostgreSQL metadata

## Trust boundaries

- internet-facing decoys are isolated from the control plane
- analyst UI and API sit behind private ingress with auth
- data residency remains within the customer environment
