from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HONEYPOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Enterprise Honeynet Control Plane"
    environment: Literal["dev", "staging", "prod"] = "dev"
    database_url: str = Field(
        default="postgresql+psycopg://honeynet:honeynet@localhost:5432/honeynet",
        validation_alias=AliasChoices("HONEYPOT_DATABASE_URL", "DATABASE_URL"),
    )
    analyst_bearer_token: str = "dev-analyst-token"
    ingest_api_key: str = "dev-ingest-key"
    allow_legacy_unauthenticated_ingest: bool = True
    inline_alert_processing: bool = True
    oidc_issuer_url: str | None = None
    oidc_audience: str | None = None
    oidc_algorithms: list[str] = ["RS256"]
    web_origin: str = "http://localhost:5173"
    collector_version: str = "ingest-api/0.2.0"
    default_report_format: Literal["html", "csv"] = "html"
    retention_days: int = 30
    metrics_namespace: str = "honeynet"
    heartbeat_degraded_seconds: int = 90
    heartbeat_silent_seconds: int = 180
    detection_window_minutes: int = 10
    distributed_window_minutes: int = 60
    artifact_bucket: str = "honeynet-artifacts"
    artifact_region: str = "us-east-1"
    artifact_endpoint_url: str = "http://minio:9000"
    artifact_access_key: str = "minioadmin"
    artifact_secret_key: str = "minioadmin"
    artifact_secure: bool = False
    expected_fleet_json: str = "[]"

    def expected_fleet(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(self.expected_fleet_json or "[]")
        except json.JSONDecodeError:
            return []
        return [entry for entry in raw if isinstance(entry, dict)]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
