from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from sqlalchemy.orm import Session

from ingest_api.config import Settings, get_settings
from ingest_api.database import get_db
from ingest_api.metrics import ANALYST_AUTH_FAILURES
from ingest_api.models import User


analyst_bearer = HTTPBearer(auto_error=False)


@dataclass
class AnalystIdentity:
    subject: str
    email: str | None = None
    display_name: str | None = None


def _decode_oidc_token(settings: Settings, token: str) -> dict[str, Any]:
    if not settings.oidc_issuer_url or not settings.oidc_audience:
        raise ValueError("OIDC is not configured")

    jwks_client = PyJWKClient(f"{settings.oidc_issuer_url.rstrip('/')}/.well-known/jwks.json")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=settings.oidc_algorithms,
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer_url,
    )


def require_ingest_key(
    x_ingest_key: str | None = Header(default=None, alias="X-Ingest-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    if settings.allow_legacy_unauthenticated_ingest and not x_ingest_key:
        return

    if x_ingest_key != settings.ingest_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid ingest key")


def require_analyst_identity(
    credentials: HTTPAuthorizationCredentials | None = Depends(analyst_bearer),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> AnalystIdentity:
    if credentials is None:
        ANALYST_AUTH_FAILURES.inc()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing analyst token")

    token = credentials.credentials

    if settings.oidc_issuer_url and settings.oidc_audience:
        try:
            claims = _decode_oidc_token(settings, token)
        except Exception as exc:  # noqa: BLE001
            ANALYST_AUTH_FAILURES.inc()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

        identity = AnalystIdentity(
            subject=str(claims.get("sub")),
            email=claims.get("email"),
            display_name=claims.get("name") or claims.get("preferred_username"),
        )
    else:
        if token != settings.analyst_bearer_token:
            ANALYST_AUTH_FAILURES.inc()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid analyst token")

        identity = AnalystIdentity(subject="dev-analyst", email="dev@example.com", display_name="Development Analyst")

    user = db.query(User).filter(User.subject == identity.subject).one_or_none()
    if user is None:
        user = User(subject=identity.subject, email=identity.email, display_name=identity.display_name)
        db.add(user)
    else:
        user.email = identity.email
        user.display_name = identity.display_name
        user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return identity
