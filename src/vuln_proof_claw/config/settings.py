"""Environment-backed application settings."""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from vuln_proof_claw.config.models import (
    ApiConfig,
    AppConfig,
    AssessmentConfig,
    DatabaseConfig,
    DockerConfig,
    Environment,
    LoggingConfig,
    ProviderConfig,
    WebConfig,
    WorkerRuntimeConfig,
)

WILDCARD_IPV4 = str(IPv4Address(0))
WILDCARD_IPV6 = str(IPv6Address(0))
WILDCARD_API_HOSTS = frozenset({WILDCARD_IPV4, WILDCARD_IPV6, f"[{WILDCARD_IPV6}]"})


class Settings(BaseSettings):
    """Root application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="VULN_PROOF_CLAW_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    app: AppConfig = AppConfig()
    api: ApiConfig = ApiConfig()
    assessment: AssessmentConfig = AssessmentConfig()
    web: WebConfig = WebConfig()
    database: DatabaseConfig = DatabaseConfig()
    docker: DockerConfig = DockerConfig()
    logging: LoggingConfig = LoggingConfig()
    provider: ProviderConfig = ProviderConfig()

    @model_validator(mode="after")
    def validate_production_safety(self) -> Settings:
        """Reject combinations that make an unfinished API publicly reachable."""
        if self.app.environment is not Environment.PRODUCTION:
            return self
        if self.app.debug:
            msg = "debug mode is not allowed in production"
            raise ValueError(msg)
        if self.api.host in WILDCARD_API_HOSTS and not self.api.authentication_ready:
            msg = "wildcard API binding requires authentication readiness in production"
            raise ValueError(msg)
        if self.database.echo:
            msg = "database query echo is not allowed in production"
            raise ValueError(msg)
        if self.assessment.enabled and not self.api.authentication_ready:
            msg = "passive assessment requires authentication readiness in production"
            raise ValueError(msg)
        return self

    def worker_runtime(self) -> WorkerRuntimeConfig:
        """Return the credential-free configuration allowed in workers."""
        return WorkerRuntimeConfig(
            image=self.docker.worker_image,
            network=self.docker.worker_network,
            timeout_seconds=self.docker.default_timeout_seconds,
        )


@lru_cache(maxsize=1)
def load_settings() -> Settings:
    """Load and cache settings for the current process."""
    return Settings()
