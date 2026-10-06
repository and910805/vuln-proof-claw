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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

if TYPE_CHECKING:
    from vuln_proof_claw.agent.differential import IdentityRole

#: The anonymous identity's name, kept here as a literal rather than imported.
#: agent.differential is the module that defines it, but importing it at module scope
#: makes config depend on agent — and since agent's package __init__ pulls in the
#: controller, which reaches back to this module, importing config.identities first
#: fails with a partially initialised module. Config is the lower layer; it should not
#: need the upper one loaded to describe a file format.
ANONYMOUS = "anonymous"

MAXIMUM_DEFINITION_BYTES = 256 * 1024
_ENV_REFERENCE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_PLACEHOLDER = re.compile(r"\{(username|password|csrf)\}")


class IdentityDefinitionError(Exception):
    """Raised when an identity file cannot be read or is invalid."""


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _variable_of(value: str) -> str | None:
    """Return the environment variable a value references, or None if it is literal."""
    reference = _ENV_REFERENCE.match(value.strip())
    return reference.group(1) if reference else None


def _resolve(value: str, *, field_name: str) -> tuple[SecretStr, bool]:
    """Resolve an environment reference, or accept a literal and flag it."""
    variable = _variable_of(value)
    if variable is None:
        return (SecretStr(value), True)
    resolved = os.environ.get(variable)
    if resolved is None:
        raise IdentityDefinitionError(
            f"{field_name} references ${{{variable}}} but that variable is not set"
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
        # Imported here, not at module scope: see the note beside ANONYMOUS above.
        from vuln_proof_claw.agent.differential import IdentityRole  # noqa: PLC0415

        return IdentityRole(self.role)


class BrowserLogin(FrozenModel):
    """How to sign in through the page, for discovery that drives a browser.

    Separate from the HTTP login above because they answer different questions. That
    one describes the request to send; this describes the controls to operate. A target
    can need both, and neither is derivable from the other.

    Every selector is operator-supplied. The agent does not find its way forward by
    clicking what looks right — on one engagement the screen after sign-in puts a
    change-password button beside the one that proceeds, and the rules forbid changing
    a shared account's password.
    """

    login_url: str = Field(min_length=1, max_length=512)
    username_selector: str = Field(min_length=1, max_length=256)
    password_selector: str = Field(min_length=1, max_length=256)
    submit_selector: str = Field(min_length=1, max_length=256)
    open_selector: str | None = Field(default=None, min_length=1, max_length=256)
    """Clicked before the fields are filled, when the form is behind a landing screen."""
    continue_selector: str | None = Field(default=None, min_length=1, max_length=256)
    """Clicked after signing in, when the product stops at an identity chooser."""


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

    browser: BrowserLogin | None = None
    """How to sign in through the page, when discovery drives a browser."""

    csrf_field: str | None = Field(default=None, min_length=1, max_length=128)
    """Name of the hidden input carrying an anti-forgery token, when the form has one.

    Set this and put ``{csrf}`` in the body. The session will fetch the page first,
    read that field's value, and send it with the credentials — which is what a browser
    does, and without it a login form protected this way simply rejects every attempt.
    """

    csrf_path: str | None = None
    """Page to read the token from, when it is not the login path itself."""

    token_field: str | None = Field(default=None, min_length=1, max_length=128)
    """Where the access token sits in the login response, for bearer-token APIs.

    Dotted, so ``data.accessToken`` reaches into a nested object. Set this and the
    session carries ``Authorization: Bearer <token>`` instead of a cookie — which is
    how a single-page application that keeps no session cookie authenticates, and
    without it such a target cannot be tested as a logged-in identity at all.
    """

    @field_validator("path")
    @classmethod
    def require_absolute_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("login path must be absolute")
        return value

    @field_validator("csrf_path")
    @classmethod
    def require_absolute_csrf_path(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("/"):
            raise ValueError("csrf path must be absolute")
        return value

    @model_validator(mode="after")
    def require_credential_placeholders(self) -> LoginFlow:
        found = {match.group(1) for match in _PLACEHOLDER.finditer(self.body)}
        missing = {"username", "password"} - found
        if missing:
            raise ValueError(f"login body is missing placeholder(s): {sorted(missing)}")
        # The two have to agree. A {csrf} with nowhere to read it from would send the
        # literal placeholder as the token; a csrf_field with no placeholder would fetch
        # a page and silently drop what it found.
        if ("csrf" in found) != (self.csrf_field is not None):
            raise ValueError(
                "csrf_field and a {csrf} placeholder in the body must be set together"
            )
        return self

    @property
    def token_path(self) -> str:
        """Where to read the anti-forgery token from."""
        return self.csrf_path or self.path

    def render(self, username: str, password: str, csrf: str = "") -> str:
        """Substitute credentials into the body template.

        Returns a plain string because it is handed straight to the transport and never
        retained. Callers must not log or store the result.
        """
        return (
            self.body.replace("{username}", username)
            .replace("{password}", password)
            .replace("{csrf}", csrf)
        )


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


@dataclass(frozen=True, slots=True)
class CredentialSlot:
    """One credential an engagement needs, and whether it has been supplied.

    Carries variable *names* only. Nothing here holds or can print a secret, which is
    what makes it safe to show an operator, write to a status report, or log.
    """

    identity: str
    role: str
    username_variable: str | None
    password_variable: str | None
    satisfied: bool
    literal_in_file: bool

    @property
    def pending_variables(self) -> tuple[str, ...]:
        """The variables an operator still has to set, in the order they are read."""
        if self.satisfied:
            return ()
        return tuple(
            variable
            for variable in (self.username_variable, self.password_variable)
            if variable is not None and os.environ.get(variable) is None
        )


@dataclass(frozen=True, slots=True)
class CredentialResolution:
    """What could be resolved, and what is still waiting on a human.

    An unattended agent should not fall over because one identity has no password yet.
    It should do the work that identity is not needed for, and say plainly what it is
    missing — so this reports rather than raises.
    """

    resolved: dict[str, ResolvedCredential]
    slots: tuple[CredentialSlot, ...]

    @property
    def pending(self) -> tuple[CredentialSlot, ...]:
        return tuple(slot for slot in self.slots if not slot.satisfied)

    @property
    def literals(self) -> tuple[str, ...]:
        return tuple(slot.identity for slot in self.slots if slot.literal_in_file)

    @property
    def complete(self) -> bool:
        return not self.pending


def inspect_credentials(bundle: IdentityBundle) -> CredentialResolution:
    """Resolve what is available and describe what is not.

    Never raises for a missing variable: a credential nobody has supplied yet is a
    normal state for a long-running agent, not an error in the file.
    """
    resolved: dict[str, ResolvedCredential] = {}
    slots: list[CredentialSlot] = []

    for identity in bundle.identities:
        if identity.credentials is None:
            continue
        username_raw = identity.credentials.username
        password_raw = identity.credentials.password.get_secret_value()
        username_variable = _variable_of(username_raw)
        password_variable = _variable_of(password_raw)

        username_value = (
            os.environ.get(username_variable)
            if username_variable is not None
            else username_raw
        )
        password_value = (
            os.environ.get(password_variable)
            if password_variable is not None
            else password_raw
        )
        satisfied = bool(username_value) and bool(password_value)
        literal = password_variable is None

        slots.append(
            CredentialSlot(
                identity=identity.name,
                role=identity.role,
                username_variable=username_variable,
                password_variable=password_variable,
                satisfied=satisfied,
                literal_in_file=literal,
            )
        )
        if satisfied:
            resolved[identity.name] = ResolvedCredential(
                username=SecretStr(username_value or ""),
                password=SecretStr(password_value or ""),
                literal_in_file=literal,
            )

    return CredentialResolution(resolved=resolved, slots=tuple(slots))


def resolve_credentials(
    bundle: IdentityBundle,
) -> tuple[dict[str, ResolvedCredential], tuple[str, ...]]:
    """Resolve every credential, refusing when one is missing.

    The strict form, for callers that cannot proceed without a full set.
    :func:`inspect_credentials` is the one an unattended run should use.
    """
    resolution = inspect_credentials(bundle)
    if resolution.pending:
        missing = ", ".join(
            f"{slot.identity} needs {' and '.join(slot.pending_variables)}"
            for slot in resolution.pending
        )
        raise IdentityDefinitionError(f"credentials are not supplied: {missing}")
    return (resolution.resolved, resolution.literals)


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
