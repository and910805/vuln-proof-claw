"""Operator-supplied test identities and the login flow that authenticates them.

Credentials enter the system here and are immediately wrapped in ``SecretStr``. They
are never placed on a request object, never written to the evidence chain, and never
rendered by ``repr``. Only the transport layer reads them, at the moment of sending.

The preferred form is an environment reference (``${VAR}``) so the file itself can live
beside the engagement definition without holding secrets. A literal password is accepted
for convenience but reported, so an operator is told when a file contains one.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from vuln_proof_claw.agent.differential import ANONYMOUS, IdentityRole

MAXIMUM_DEFINITION_BYTES = 256 * 1024
_ENV_REFERENCE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_PLACEHOLDER = re.compile(r"\{(username|password)\}")


class IdentityDefinitionError(Exception):
    """Raised when an identity file cannot be read or is invalid."""


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _resolve(value: str, *, field_name: str) -> tuple[SecretStr, bool]:
    """Resolve an environment reference, or accept a literal and flag it."""
    reference = _ENV_REFERENCE.match(value.strip())
    if reference is None:
        return (SecretStr(value), True)
    resolved = os.environ.get(reference.group(1))
    if resolved is None:
        raise IdentityDefinitionError(
            f"{field_name} references ${{{reference.group(1)}}} but that variable is not set"
        )
    return (SecretStr(resolved), False)


class CredentialDefinition(FrozenModel):
    """A username and password pair for one test identity.

    ``password`` is a ``SecretStr`` from the moment it is parsed, so the bundle cannot
    leak it through ``repr`` or ``model_dump`` while it waits to be resolved.
    """

    username: str = Field(min_length=1, max_length=320)
    password: SecretStr = Field(repr=False)

    @field_validator("password")
    @classmethod
    def require_a_value(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("password must not be empty")
        return value


class IdentityDefinition(FrozenModel):
    """One identity the differential engine may act as."""

    name: str = Field(min_length=1, max_length=64)
    role: Literal["anonymous", "user", "privileged"] = "user"
    credentials: CredentialDefinition | None = None
    owns: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_credentials_unless_anonymous(self) -> IdentityDefinition:
        if self.name == ANONYMOUS:
            if self.credentials is not None:
                raise ValueError("the anonymous identity must not carry credentials")
        elif self.credentials is None:
            raise ValueError(f"identity '{self.name}' requires credentials")
        return self

    @property
    def identity_role(self) -> IdentityRole:
        return IdentityRole(self.role)


class LoginFlow(FrozenModel):
    """How to exchange credentials for a session on one target.

    Every field is operator-supplied because login is target-specific. The agent never
    guesses a login endpoint: an unconfigured target simply has no authenticated
    identities.
    """

    method: Literal["POST"] = "POST"
    path: str = Field(min_length=1, max_length=512)
    content_type: Literal["application/json", "application/x-www-form-urlencoded"] = (
        "application/json"
    )
    body: str = Field(min_length=1, max_length=4096, repr=False)
    success_statuses: tuple[int, ...] = (200, 204, 302)
    session_cookies: tuple[str, ...] = ()
    failure_marker: str | None = None

    @field_validator("path")
    @classmethod
    def require_absolute_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("login path must be absolute")
        return value

    @model_validator(mode="after")
    def require_credential_placeholders(self) -> LoginFlow:
        found = {match.group(1) for match in _PLACEHOLDER.finditer(self.body)}
        missing = {"username", "password"} - found
        if missing:
            raise ValueError(f"login body is missing placeholder(s): {sorted(missing)}")
        return self

    def render(self, username: str, password: str) -> str:
        """Substitute credentials into the body template.

        Returns a plain string because it is handed straight to the transport and never
        retained. Callers must not log or store the result.
        """
        return self.body.replace("{username}", username).replace("{password}", password)


class IdentityBundle(FrozenModel):
    """Everything needed to act as several identities against one target."""

    base_url: str = Field(min_length=1, max_length=512)
    login: LoginFlow | None = None
    identities: tuple[IdentityDefinition, ...]

    @model_validator(mode="after")
    def require_a_usable_set(self) -> IdentityBundle:
        names = [identity.name for identity in self.identities]
        if len(names) != len(set(names)):
            raise ValueError("identity names must be unique")
        if not names:
            raise ValueError("at least one identity is required")
        if any(identity.credentials for identity in self.identities) and self.login is None:
            raise ValueError("identities with credentials require a login flow")
        return self

    def named(self, name: str) -> IdentityDefinition | None:
        for identity in self.identities:
            if identity.name == name:
                return identity
        return None


class ResolvedCredential(FrozenModel):
    """A credential after environment resolution. Never serialised."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    username: SecretStr
    password: SecretStr
    literal_in_file: bool = False


def resolve_credentials(
    bundle: IdentityBundle,
) -> tuple[dict[str, ResolvedCredential], tuple[str, ...]]:
    """Resolve every credential, reporting which identities held literals in the file."""
    resolved: dict[str, ResolvedCredential] = {}
    literals: list[str] = []
    for identity in bundle.identities:
        if identity.credentials is None:
            continue
        username, _ = _resolve(
            identity.credentials.username, field_name=f"{identity.name}.username"
        )
        password, literal = _resolve(
            identity.credentials.password.get_secret_value(),
            field_name=f"{identity.name}.password",
        )
        resolved[identity.name] = ResolvedCredential(
            username=username, password=password, literal_in_file=literal
        )
        if literal:
            literals.append(identity.name)
    return (resolved, tuple(literals))


def parse_identity_bundle(document: str) -> IdentityBundle:
    """Parse an identity bundle from YAML text."""
    if len(document.encode()) > MAXIMUM_DEFINITION_BYTES:
        raise IdentityDefinitionError("identity definition exceeds the maximum size")
    try:
        payload: Any = yaml.safe_load(document)
    except yaml.YAMLError as error:
        raise IdentityDefinitionError("identity definition is not valid YAML") from error
    if not isinstance(payload, dict):
        raise IdentityDefinitionError("identity definition must be a mapping")
    try:
        return IdentityBundle.model_validate(payload)
    except ValueError as error:
        raise IdentityDefinitionError(str(error)) from error


def load_identity_bundle(path: Path) -> IdentityBundle:
    """Read and validate an identity bundle file."""
    try:
        document = path.read_text(encoding="utf-8")
    except OSError as error:
        raise IdentityDefinitionError("identity definition could not be read") from error
    return parse_identity_bundle(document)


__all__ = [
    "CredentialDefinition",
    "IdentityBundle",
    "IdentityDefinition",
    "IdentityDefinitionError",
    "LoginFlow",
    "ResolvedCredential",
    "load_identity_bundle",
    "parse_identity_bundle",
    "resolve_credentials",
]
