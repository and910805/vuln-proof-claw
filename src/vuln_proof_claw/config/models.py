"""Configuration value models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


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
    operator_token: SecretStr | None = Field(default=None, min_length=32)
    approver_token: SecretStr | None = Field(default=None, min_length=32)

    @model_validator(mode="after")
    def validate_authentication(self) -> ApiConfig:
        """Require two distinct credentials before authentication is called ready."""
        tokens = (self.operator_token, self.approver_token)
        if self.authentication_ready and any(token is None for token in tokens):
            raise ValueError("authentication readiness requires operator and approver tokens")
        operator_token = self.operator_token
        approver_token = self.approver_token
        if (
            operator_token is not None
            and approver_token is not None
            and operator_token.get_secret_value() == approver_token.get_secret_value()
        ):
            raise ValueError("operator and approver tokens must be distinct")
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

    worker_image: str = "vuln-proof-claw-worker:dev"
    worker_network: str = "vuln-proof-claw-workers"
    default_timeout_seconds: int = Field(default=300, ge=1, le=10_800)


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
