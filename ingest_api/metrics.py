from __future__ import annotations

from prometheus_client import Counter, Histogram

from ingest_api.config import get_settings


settings = get_settings()

INGEST_REQUESTS = Counter(
    f"{settings.metrics_namespace}_ingest_requests_total",
    "Total ingest requests received",
)
INGEST_FAILURES = Counter(
    f"{settings.metrics_namespace}_ingest_failures_total",
    "Total ingest requests rejected or failed",
)
ANALYST_AUTH_FAILURES = Counter(
    f"{settings.metrics_namespace}_analyst_auth_failures_total",
    "Total analyst auth failures",
)
INGEST_LATENCY = Histogram(
    f"{settings.metrics_namespace}_ingest_processing_seconds",
    "Time spent processing ingest events",
)

