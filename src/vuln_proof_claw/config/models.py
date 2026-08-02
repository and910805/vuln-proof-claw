"""Configuration value models."""

from __future__ import annotations

import re
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

_ENGINE_TOKEN_MINIMUM_LENGTH = 32
_ENGINE_TOKEN_MAXIMUM_LENGTH = 4096
_VISIBLE_ASCII_MINIMUM = 33
_VISIBLE_ASCII_MAXIMUM = 126
_MINIMUM_TCP_PORT = 1
_MAXIMUM_TCP_PORT = 65_535
_DIGEST_PINNED_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{0,180}@sha256:[a-f0-9]{64}$"
)
_WORKER_NETWORK_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class Environment(StrEnum):
    """Supported application environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class FrozenConfigModel(BaseModel):
    """Base class for immutable configuration sections."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class AppConfig(FrozenConfigModel):
    """Application-level behavior."""

    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False


class ApiConfig(FrozenConfigModel):
    """REST API listener configuration."""

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    authentication_ready: bool = False
    operator_identity: str = Field(default="local-operator", min_length=1, max_length=320)
    approver_identity: str = Field(default="local-approver", min_length=1, max_length=320)
    evidence_reader_identity: str = Field(
        default="local-evidence-reader", min_length=1, max_length=320
    )
    operator_token: SecretStr | None = Field(default=None, min_length=32)
    approver_token: SecretStr | None = Field(default=None, min_length=32)
    evidence_reader_token: SecretStr | None = Field(default=None, min_length=32)

    @property
    def evidence_access_ready(self) -> bool:
        """Return whether the separately authenticated raw-evidence path is enabled."""
        return self.authentication_ready and self.evidence_reader_token is not None

    @model_validator(mode="after")
    def validate_authentication(self) -> ApiConfig:
        """Require two distinct credentials before authentication is called ready."""
        tokens = (self.operator_token, self.approver_token)
        if self.authentication_ready and any(token is None for token in tokens):
            raise ValueError("authentication readiness requires operator and approver tokens")
        configured = [
            token.get_secret_value() for token in (*tokens, self.evidence_reader_token) if token
        ]
        if len(configured) != len(set(configured)):
            raise ValueError("operator, approver, and evidence-reader tokens must be distinct")
        return self


class WebConfig(FrozenConfigModel):
    """Bundled Web console configuration."""

    enabled: bool = True
    static_directory: Path | None = None


class DatabaseConfig(FrozenConfigModel):
    """Control-plane database configuration."""

    url: SecretStr = SecretStr(
        "postgresql+psycopg://vuln_proof_claw:vuln_proof_claw@127.0.0.1:5432/vuln_proof_claw"
    )
    pool_size: int = Field(default=5, ge=1, le=100)
    echo: bool = False


class DockerConfig(FrozenConfigModel):
    """Worker-manager Docker configuration."""

    runtime_enabled: bool = False
    worker_image: str = "vuln-proof-claw-worker:dev"
    worker_network: str = "vuln-proof-claw-workers"
    default_timeout_seconds: int = Field(default=300, ge=1, le=10_800)
    allowed_capabilities: tuple[str, ...] = ("http_client",)
    maximum_memory_megabytes: int = Field(default=2048, ge=64, le=32_768)
    maximum_cpu_count: float = Field(default=2.0, gt=0, le=32)
    maximum_process_limit: int = Field(default=256, ge=16, le=4096)
    maximum_request_bytes: int = Field(default=256 * 1024, ge=1024, le=1024 * 1024)
    maximum_output_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    task_tmpfs_megabytes: int = Field(default=64, ge=16, le=1024)
    stop_grace_seconds: int = Field(default=5, ge=1, le=30)


class EngineGatewayConfig(FrozenConfigModel):
    """Authenticated HTTP boundary to the privileged container Engine service."""

    url: str | None = None
    token: SecretStr | None = None
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    maximum_response_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=64 * 1024,
        le=32 * 1024 * 1024,
    )
    ca_bundle: Path | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("engine gateway URL contains an invalid port") from error
        if port is not None and not _MINIMUM_TCP_PORT <= port <= _MAXIMUM_TCP_PORT:
            raise ValueError("engine gateway URL contains an invalid port")
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("engine gateway URL must be an origin without credentials")
        if parsed.scheme == "http" and not _is_loopback_literal(parsed.hostname):
            raise ValueError("unencrypted engine gateway URL requires a loopback IP literal")
        return normalized

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: SecretStr | None) -> SecretStr | None:
        return _validate_engine_token(value)

    @model_validator(mode="after")
    def require_complete_credentials(self) -> EngineGatewayConfig:
        if (self.url is None) != (self.token is None):
            raise ValueError("engine gateway URL and token must be configured together")
        return self

    @property
    def ready(self) -> bool:
        return self.url is not None and self.token is not None


class EngineServerConfig(FrozenConfigModel):
    """Fail-closed listener and admission limits for the privileged gateway service."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8081, ge=1, le=65_535)
    token: SecretStr | None = None
    maximum_request_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=64 * 1024,
        le=4 * 1024 * 1024,
    )
    maximum_concurrent_operations: int = Field(default=16, ge=1, le=128)
    queue_timeout_seconds: float = Field(default=2.0, gt=0, le=30)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        normalized = value.strip()
        if not _is_loopback_literal(normalized):
            raise ValueError("Engine server host must be a loopback IP literal")
        return normalized

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: SecretStr | None) -> SecretStr | None:
        return _validate_engine_token(value)

    @model_validator(mode="after")
    def require_token_when_enabled(self) -> EngineServerConfig:
        if self.enabled and self.token is None:
            raise ValueError("enabled Engine server requires an authentication token")
        return self


class DockerEngineBackendConfig(FrozenConfigModel):
    """Explicit local Docker Engine adapter policy for the privileged process."""

    enabled: bool = False
    socket_path: str = "/var/run/docker.sock"
    api_version: Literal["v1.44"] = "v1.44"
    allowed_image: str | None = None
    allowed_network: str | None = None
    request_timeout_seconds: int = Field(default=30, ge=1, le=120)
    maximum_response_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=64 * 1024,
        le=32 * 1024 * 1024,
    )

    @field_validator("socket_path")
    @classmethod
    def validate_socket_path(cls, value: str) -> str:
        normalized = value.strip()
        path = PurePosixPath(normalized)
        if not path.is_absolute() or str(path) != normalized or "\0" in normalized:
            raise ValueError("Docker Engine socket path must be absolute")
        return normalized

    @field_validator("allowed_image")
    @classmethod
    def validate_allowed_image(cls, value: str | None) -> str | None:
        if value is not None and not _DIGEST_PINNED_IMAGE_PATTERN.fullmatch(value):
            raise ValueError("Docker Engine backend image must be digest-pinned")
        return value

    @field_validator("allowed_network")
    @classmethod
    def validate_allowed_network(cls, value: str | None) -> str | None:
        if value is not None and not _WORKER_NETWORK_PATTERN.fullmatch(value):
            raise ValueError("Docker Engine backend network is invalid")
        return value

    @model_validator(mode="after")
    def require_complete_policy_when_enabled(self) -> DockerEngineBackendConfig:
        if self.enabled and (self.allowed_image is None or self.allowed_network is None):
            raise ValueError(
                "enabled Docker Engine backend requires an allowed image and network"
            )
        return self


def _is_loopback_literal(hostname: str) -> bool:
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_engine_token(value: SecretStr | None) -> SecretStr | None:
    if value is not None:
        secret = value.get_secret_value()
        if not (
            _ENGINE_TOKEN_MINIMUM_LENGTH
            <= len(secret)
            <= _ENGINE_TOKEN_MAXIMUM_LENGTH
        ):
            raise ValueError("Engine token must contain 32 to 4096 characters")
        if any(
            not _VISIBLE_ASCII_MINIMUM <= ord(character) <= _VISIBLE_ASCII_MAXIMUM
            for character in secret
        ):
            raise ValueError("Engine token must use visible ASCII characters")
    return value


class AssessmentConfig(FrozenConfigModel):
    """Explicit opt-in limits for the passive URL assessment preview."""

    enabled: bool = False
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1, le=10 * 1024 * 1024)
    user_agent: str = Field(default="vuln-proof-claw/0.0.19", min_length=1, max_length=255)

    @field_validator("user_agent")
    @classmethod
    def validate_user_agent(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("assessment user agent must not be blank")
        if any(character in normalized for character in ("\r", "\n", "\x00")):
            raise ValueError("assessment user agent contains a control delimiter")
        return normalized


class LoggingConfig(FrozenConfigModel):
    """Structured logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["human", "json"] = "human"


class ProviderConfig(FrozenConfigModel):
    """Control-plane provider placeholder configuration."""

    name: str = "openai-compatible"
    base_url: str | None = None
    model: str | None = None
    api_key: SecretStr | None = None


class WorkerRuntimeConfig(FrozenConfigModel):
    """Configuration safe to serialize into a worker request."""

    image: str
    network: str
    timeout_seconds: int
