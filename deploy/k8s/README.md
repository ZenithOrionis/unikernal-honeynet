# Kubernetes deployment

## Control-plane components

- `ingest-api` FastAPI service
- `worker` background alert materializer
- `analyst-web` React analyst UI
- optional in-cluster PostgreSQL for small installs

## Quick install

```bash
helm upgrade --install honeynet ./deploy/k8s/chart -f ./deploy/k8s/values-dev.yaml
```

For production, supply real image tags, TLS secrets, ingress auth annotations, and either disable the bundled PostgreSQL stateful set or replace it with a managed PostgreSQL endpoint.

