"""Bearer authentication and separation-of-duty dependencies."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from vuln_proof_claw.config.models import ApiConfig
from vuln_proof_claw.config.settings import Settings

bearer_scheme = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]


class PrincipalRole(StrEnum):
    OPERATOR = "operator"
    APPROVER = "approver"
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    identity: str
    role: PrincipalRole


def _api_config(request: Request) -> ApiConfig:
    settings = cast("Settings", request.app.state.settings)
    return settings.api


def _unauthorized(detail: str = "authentication_required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _matches(credentials: HTTPAuthorizationCredentials | None, expected: SecretStr | None) -> bool:
    if credentials is None or credentials.scheme.lower() != "bearer" or expected is None:
        return False
    return secrets.compare_digest(credentials.credentials, expected.get_secret_value())


def require_authenticated_if_configured(
    request: Request,
    credentials: BearerCredentials,
) -> AuthenticatedPrincipal:
    """Protect the control-plane API when authentication readiness is enabled."""
    config = _api_config(request)
    if not config.authentication_ready:
        return AuthenticatedPrincipal("api:unauthenticated", PrincipalRole.LOCAL)
    if _matches(credentials, config.operator_token):
        return AuthenticatedPrincipal(config.operator_identity, PrincipalRole.OPERATOR)
    if _matches(credentials, config.approver_token):
        return AuthenticatedPrincipal(config.approver_identity, PrincipalRole.APPROVER)
    raise _unauthorized()


def require_operator_if_configured(
    request: Request,
    credentials: BearerCredentials,
) -> AuthenticatedPrincipal:
    """Require the operator role in authenticated deployments, preserving local mode."""
    config = _api_config(request)
    if not config.authentication_ready:
        return AuthenticatedPrincipal("api:unauthenticated", PrincipalRole.LOCAL)
    if not _matches(credentials, config.operator_token):
        raise _unauthorized("operator_authentication_required")
    return AuthenticatedPrincipal(config.operator_identity, PrincipalRole.OPERATOR)


def require_approver(
    request: Request,
    credentials: BearerCredentials,
) -> AuthenticatedPrincipal:
    """Require configured, distinct approval authority for a policy mutation."""
    config = _api_config(request)
    if not config.authentication_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication_not_ready",
        )
    if not _matches(credentials, config.approver_token):
        raise _unauthorized("approver_authentication_required")
    return AuthenticatedPrincipal(config.approver_identity, PrincipalRole.APPROVER)
