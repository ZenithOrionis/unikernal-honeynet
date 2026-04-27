# Security and Governance

## Authentication

- analyst access uses dev bearer token locally or OIDC in production
- ingest uses a separate ingest API key

## Transport and ingress

- analyst UI and API are intended for private ingress with TLS
- decoys remain public-facing and isolated from the analyst plane

## Secrets

- Kubernetes secrets hold database, ingest, and artifact-store credentials
- MinIO remains self-hosted by default and S3-compatible

## Retention and auditability

- PostgreSQL retains normalized telemetry and analyst metadata
- MinIO stores exported evidence, management summaries, and blocklists
- artifact metadata remains queryable in PostgreSQL for audit trails

## Data residency

The intended production model keeps the entire trust boundary customer-side:
- customer-owned edge decoys
- customer-owned Kubernetes control plane
- customer-owned PostgreSQL
- customer-owned MinIO
