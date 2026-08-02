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
    DockerEngineBackendConfig,
    EngineGatewayConfig,
    EngineServerConfig,
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
    engine_gateway: EngineGatewayConfig = EngineGatewayConfig()
    engine_server: EngineServerConfig = EngineServerConfig()
    docker_engine_backend: DockerEngineBackendConfig = DockerEngineBackendConfig()
    logging: LoggingConfig = LoggingConfig()
    provider: ProviderConfig = ProviderConfig()

    @model_validator(mode="after")
    def validate_production_safety(self) -> Settings:
        """Reject combinations that make an unfinished API publicly reachable."""
        self._validate_engine_configuration()
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
        if self.docker.runtime_enabled and not self.api.authentication_ready:
            msg = "worker runtime requires authentication readiness in production"
            raise ValueError(msg)
        return self

    def _validate_engine_configuration(self) -> None:
        if self.docker.runtime_enabled:
            if not self.engine_gateway.ready:
                msg = "worker runtime requires an authenticated Engine gateway"
                raise ValueError(msg)
            engine_token = self.engine_gateway.token
            api_tokens = (
                self.api.operator_token,
                self.api.approver_token,
                self.api.evidence_reader_token,
            )
            if engine_token is not None and any(
                token is not None
                and token.get_secret_value() == engine_token.get_secret_value()
                for token in api_tokens
            ):
                msg = "engine gateway token must be distinct from API tokens"
                raise ValueError(msg)
        if self.engine_server.enabled:
            server_token = self.engine_server.token
            api_tokens = (
                self.api.operator_token,
                self.api.approver_token,
                self.api.evidence_reader_token,
            )
            if server_token is not None and any(
                token is not None
                and token.get_secret_value() == server_token.get_secret_value()
                for token in api_tokens
            ):
                msg = "Engine server token must be distinct from API tokens"
                raise ValueError(msg)
            gateway_token = self.engine_gateway.token
            if (
                server_token is not None
                and gateway_token is not None
                and server_token.get_secret_value() != gateway_token.get_secret_value()
            ):
                msg = "co-configured Engine client and server tokens must match"
                raise ValueError(msg)
        if self.docker_engine_backend.enabled and not self.engine_server.enabled:
            msg = "Docker Engine backend requires the Engine server"
            raise ValueError(msg)

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
