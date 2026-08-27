"""Strict, digest-bound contracts for high-impact security tools."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

_COMMAND_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}$")
_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_FORBIDDEN_ARGUMENT_DELIMITERS = ("\x00", "\r", "\n")
_MAXIMUM_COMMAND_ARGUMENT_LENGTH = 2048
_MAXIMUM_TCP_PORT = 65_535


class ToolParameters(BaseModel):
    """Immutable strict base for one tool-specific parameter set."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ShellCommandParameters(ToolParameters):
    """Exact argv execution; this deliberately never accepts a shell command line."""

    kind: Literal["shell_command"] = "shell_command"
    executable: str = Field(min_length=1, max_length=64)
    arguments: tuple[str, ...] = Field(default=(), max_length=64)
    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        if not _COMMAND_PATTERN.fullmatch(value):
            raise ValueError("executable must be a basename, not a path or shell expression")
        return value

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) > _MAXIMUM_COMMAND_ARGUMENT_LENGTH
            or any(delimiter in value for delimiter in _FORBIDDEN_ARGUMENT_DELIMITERS)
            for value in values
        ):
            raise ValueError("command arguments exceed limits or contain control delimiters")
        return values


class PythonExecuteParameters(ToolParameters):
    """Python source intended only for a disposable, network-restricted Worker."""

    kind: Literal["python_execute"] = "python_execute"
    source: str = Field(min_length=1, max_length=32_768, repr=False)
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    timeout_seconds: int = Field(default=60, ge=1, le=300)

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("python source contains a NUL byte")
        return value


class NmapParameters(ToolParameters):
    """Typed Nmap connect-scan profile without raw or evasion flags."""

    kind: Literal["nmap"] = "nmap"
    ports: tuple[int, ...] = Field(default=(80, 443), min_length=1, max_length=1024)
    service_detection: bool = True
    scripts: tuple[str, ...] = Field(default=(), max_length=20)
    timeout_seconds: int = Field(default=300, ge=10, le=1800)

    @field_validator("ports")
    @classmethod
    def normalize_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > _MAXIMUM_TCP_PORT for port in values):
            raise ValueError("nmap port is outside the TCP range")
        return tuple(sorted(set(values)))

    @field_validator("scripts")
    @classmethod
    def validate_scripts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _REFERENCE_PATTERN.fullmatch(value) for value in values):
            raise ValueError("nmap script names must be registry references")
        return tuple(dict.fromkeys(values))


# The probe names this contract offers. Each maps to exactly one httpx flag in
# the executor; naming them here keeps the parameter surface independent of the
# tool's flag spelling.
HttpxProbe = Literal[
    "status_code",
    "content_length",
    "title",
    "web_server",
    "tech_detect",
    "tls_grab",
    "response_time",
]

_DEFAULT_HTTPX_PROBES: Final[tuple[HttpxProbe, ...]] = (
    "content_length",
    "status_code",
    "tech_detect",
    "tls_grab",
    "title",
    "web_server",
)


class HttpxParameters(ToolParameters):
    """Probe exactly one already-approved target.

    What this contract does *not* offer is the point of it. There is no target
    file, no port list, no extra paths and no proxy, because every one of those
    would let a single approved action reach something the approval never named.
    Redirects are not followed either: a redirect points at a different target,
    and a different target needs its own scope check and its own approval.
    """

    kind: Literal["httpx"] = "httpx"
    probes: tuple[HttpxProbe, ...] = Field(default=_DEFAULT_HTTPX_PROBES, min_length=1)
    method: Literal["GET", "HEAD"] = "GET"
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    retries: int = Field(default=1, ge=0, le=3)
    rate_limit_per_second: int = Field(default=10, ge=1, le=150)

    @field_validator("probes")
    @classmethod
    def normalize_probes(cls, values: tuple[HttpxProbe, ...]) -> tuple[HttpxProbe, ...]:
        # Sorted and deduplicated so the same request written in a different
        # order digests the same. Without this, replaying an approved action
        # with its probes listed differently is refused as a digest mismatch.
        return tuple(sorted(set(values)))


class PasswordTestParameters(ToolParameters):
    """Rate-limited credential validation using secret references, never raw passwords."""

    kind: Literal["password_test"] = "password_test"
    protocol: Literal["http_basic", "http_form", "ssh"]
    usernames: tuple[str, ...] = Field(min_length=1, max_length=100)
    secret_refs: tuple[str, ...] = Field(min_length=1, max_length=100, repr=False)
    maximum_attempts: int = Field(default=30, ge=1, le=100)
    attempts_per_minute: int = Field(default=10, ge=1, le=30)
    stop_on_success: bool = True

    @field_validator("usernames", "secret_refs")
    @classmethod
    def validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _REFERENCE_PATTERN.fullmatch(value) for value in values):
            raise ValueError("credential inputs must be bounded names or secret references")
        return tuple(dict.fromkeys(values))

    @model_validator(mode="after")
    def cap_attempt_space(self) -> PasswordTestParameters:
        if self.maximum_attempts > len(self.usernames) * len(self.secret_refs):
            raise ValueError("maximum_attempts exceeds the declared credential pair space")
        return self


class ExploitPocParameters(ToolParameters):
    """Digest-pinned PoC validation without embedding an exploit payload in the request."""

    kind: Literal["exploit_poc"] = "exploit_poc"
    poc_id: str = Field(min_length=1, max_length=255)
    artifact_sha256: str
    cve: str | None = None
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    success_signal: str = Field(min_length=1, max_length=512)
    maximum_attempts: int = Field(default=1, ge=1, le=10)

    @field_validator("poc_id")
    @classmethod
    def validate_poc_id(cls, value: str) -> str:
        if not _REFERENCE_PATTERN.fullmatch(value):
            raise ValueError("poc_id must be a registry reference")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("artifact_sha256 must be a lowercase SHA-256 digest")
        return value

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, value: str | None) -> str | None:
        if value is not None and not _CVE_PATTERN.fullmatch(value):
            raise ValueError("cve must use the CVE-YYYY-NNNN format")
        return value.upper() if value else None


ToolParameterUnion = Annotated[
    ShellCommandParameters
    | PythonExecuteParameters
    | NmapParameters
    | HttpxParameters
    | PasswordTestParameters
    | ExploitPocParameters,
    Field(discriminator="kind"),
]
_PARAMETER_ADAPTER: TypeAdapter[ToolParameterUnion] = TypeAdapter(ToolParameterUnion)


class ToolInvocation(BaseModel):
    """Canonical tool request suitable for policy review and approval binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    target: str
    parameters: ToolParameterUnion
    parameter_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def validate_tool_invocation(tool: str, target: str, parameters: dict[str, Any]) -> ToolInvocation:
    """Parse a tool contract and bind its canonical parameters to one SHA-256 digest."""
    document = {**parameters, "kind": tool}
    parsed = _PARAMETER_ADAPTER.validate_python(document)
    canonical = {
        "tool": tool,
        "target": target,
        "parameters": parsed.model_dump(mode="json"),
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ToolInvocation(
        tool=tool,
        target=target,
        parameters=parsed,
        parameter_digest=digest,
    )
