"""Configuration value models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


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


class AssessmentConfig(FrozenConfigModel):
    """Explicit opt-in limits for the passive URL assessment preview."""

    enabled: bool = False
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1, le=10 * 1024 * 1024)
    user_agent: str = Field(default="vuln-proof-claw/0.0.15", min_length=1, max_length=255)

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
