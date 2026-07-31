"""Versioned control-plane-to-worker protocol."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    ApprovalId,
    ArtifactId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.policy.scope import (
    EngagementScope,
    evaluate_scope,
    normalize_hostname,
    normalize_network,
    normalize_path,
    normalize_port,
    normalize_scheme,
    normalize_target,
)

PROTOCOL_VERSION: Literal["v1"] = "v1"


class ProtocolModel(BaseModel):
    """Strict immutable base for messages crossing the worker boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerLimits(ProtocolModel):
    """Resource ceilings enforced by a concrete worker runtime."""

    timeout_seconds: int = Field(ge=1, le=10_800)
    memory_megabytes: int = Field(ge=64, le=32_768)
    cpu_count: float = Field(gt=0, le=32)
    process_limit: int = Field(ge=16, le=4096)


class WorkerScope(ProtocolModel):
    """Normalized network scope that must be rechecked inside a worker."""

    allowed_hostnames: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...]
    allowed_schemes: tuple[Literal["http", "https"], ...]
    allowed_paths: tuple[str, ...] = ("/",)
    denied_hostnames: tuple[str, ...] = ()
    denied_cidrs: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()

    @field_validator("allowed_hostnames", "denied_hostnames")
    @classmethod
    def normalize_hostnames(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({normalize_hostname(value) for value in values}))

    @field_validator("allowed_cidrs", "denied_cidrs")
    @classmethod
    def normalize_cidrs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({str(normalize_network(value)) for value in values}))

    @field_validator("allowed_ports")
    @classmethod
    def normalize_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted({normalize_port(value) for value in values}))

    @field_validator("allowed_schemes")
    @classmethod
    def normalize_schemes(
        cls,
        values: tuple[Literal["http", "https"], ...],
    ) -> tuple[Literal["http", "https"], ...]:
        normalized = tuple(sorted({normalize_scheme(value) for value in values}))
        return cast("tuple[Literal['http', 'https'], ...]", normalized)

    @field_validator("allowed_paths", "denied_paths")
    @classmethod
    def normalize_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({normalize_path(value) for value in values}))

    @model_validator(mode="after")
    def require_target_boundary(self) -> WorkerScope:
        if not self.allowed_hostnames and not self.allowed_cidrs:
            raise ValueError("worker scope requires an allowed hostname or CIDR")
        if not self.allowed_ports or not self.allowed_schemes:
            raise ValueError("worker scope requires allowed ports and schemes")
        return self


class WorkerRequest(ProtocolModel):
    """One authorized, idempotent action submitted to a disposable worker."""

    protocol_version: Literal["v1"] = PROTOCOL_VERSION
    request_id: str = Field(min_length=1, max_length=255)
    engagement_id: EngagementId
    action_id: ActionId
    action_type: str = Field(min_length=1, max_length=255)
    normalized_target: str
    parameter_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    risk_level: RiskLevel
    approval_id: ApprovalId | None = None
    idempotency_key: str = Field(min_length=1, max_length=255)
    capabilities: tuple[str, ...] = ()
    scope: WorkerScope
    limits: WorkerLimits

    @field_validator("normalized_target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        if str(normalize_target(value)) != value:
            raise ValueError("normalized_target must use the canonical target format")
        return value

    @model_validator(mode="after")
    def require_high_risk_approval(self) -> WorkerRequest:
        if self.risk_level.requires_approval and self.approval_id is None:
            raise ValueError("L2-L4 worker requests require an approval_id")
        scope = EngagementScope.create(
            allowed_hostnames=self.scope.allowed_hostnames,
            allowed_cidrs=self.scope.allowed_cidrs,
            allowed_ports=self.scope.allowed_ports,
            allowed_schemes=self.scope.allowed_schemes,
            allowed_paths=self.scope.allowed_paths,
            denied_hostnames=self.scope.denied_hostnames,
            denied_cidrs=self.scope.denied_cidrs,
            denied_paths=self.scope.denied_paths,
        )
        if not evaluate_scope(self.normalized_target, scope, at=datetime.now(UTC)).allowed:
            raise ValueError("normalized_target is outside the worker scope")
        return self


class WorkerResultStatus(StrEnum):
    """Terminal worker outcomes."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    POLICY_DENIED = "policy_denied"
    WORKER_ERROR = "worker_error"


class WorkerResponse(ProtocolModel):
    """Terminal response containing references rather than raw evidence bodies."""

    protocol_version: Literal["v1"] = PROTOCOL_VERSION
    request_id: str
    engagement_id: EngagementId
    action_id: ActionId
    status: WorkerResultStatus
    started_at: datetime
    completed_at: datetime
    evidence_ids: tuple[EvidenceId, ...] = ()
    artifact_ids: tuple[ArtifactId, ...] = ()
    exit_code: int | None = None
    error_code: str | None = None

    @model_validator(mode="after")
    def validate_timestamps_and_error(self) -> WorkerResponse:
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("started_at must be timezone-aware")
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("completed_at must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be earlier than started_at")
        if self.status is not WorkerResultStatus.SUCCEEDED and not self.error_code:
            raise ValueError("non-success responses require a safe error_code")
        if self.status is WorkerResultStatus.SUCCEEDED and self.error_code is not None:
            raise ValueError("successful responses must not include an error_code")
        return self
