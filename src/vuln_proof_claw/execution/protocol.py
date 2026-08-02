"""Versioned control-plane-to-worker protocol."""

from __future__ import annotations

import base64
import binascii
import hashlib
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
from vuln_proof_claw.execution.http_contract import http_parameter_digest
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
MAXIMUM_INLINE_CAPTURE_BODY_BYTES = 512 * 1024
MAXIMUM_INLINE_CAPTURE_BODY_BASE64_CHARACTERS = (
    4 * ((MAXIMUM_INLINE_CAPTURE_BODY_BYTES + 2) // 3)
)
_MAXIMUM_HTTP_HEADER_COUNT = 100
_MAXIMUM_HTTP_HEADER_BYTES = 64 * 1024
_MAXIMUM_CAPTURE_DURATION_MS = 10_800 * 1000
_MAXIMUM_HTTP_TIMEOUT_SECONDS = 60
_ALLOWED_HTTP_REQUEST_HEADERS = frozenset({"accept", "user-agent"})


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

    def as_engagement_scope(self) -> EngagementScope:
        """Rebuild the runtime-neutral scope used for Worker-side enforcement."""
        return EngagementScope.create(
            allowed_hostnames=self.allowed_hostnames,
            allowed_cidrs=self.allowed_cidrs,
            allowed_ports=self.allowed_ports,
            allowed_schemes=self.allowed_schemes,
            allowed_paths=self.allowed_paths,
            denied_hostnames=self.denied_hostnames,
            denied_cidrs=self.denied_cidrs,
            denied_paths=self.denied_paths,
        )


class WorkerHttpAction(ProtocolModel):
    """Exact passive HTTP operation authorized for one Worker request."""

    method: Literal["GET", "HEAD"] = "GET"
    headers: tuple[tuple[str, str], ...] = Field(default=(), max_length=100)
    maximum_response_bytes: int = Field(
        default=MAXIMUM_INLINE_CAPTURE_BODY_BYTES,
        ge=1,
        le=MAXIMUM_INLINE_CAPTURE_BODY_BYTES,
    )

    @field_validator("headers")
    @classmethod
    def validate_headers(
        cls,
        values: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        return _normalize_worker_headers(values, request=True)


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
    http_action: WorkerHttpAction | None = None
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
        scope = self.scope.as_engagement_scope()
        if not evaluate_scope(self.normalized_target, scope, at=datetime.now(UTC)).allowed:
            raise ValueError("normalized_target is outside the worker scope")
        if self.action_type == "public_page_read":
            if self.risk_level is not RiskLevel.L0:
                raise ValueError("public_page_read must remain an L0 action")
            if self.http_action is None or "http_client" not in self.capabilities:
                raise ValueError("public_page_read requires one HTTP action and capability")
            if self.limits.timeout_seconds > _MAXIMUM_HTTP_TIMEOUT_SECONDS:
                raise ValueError("public_page_read timeout must not exceed 60 seconds")
        elif self.http_action is not None:
            raise ValueError("HTTP action is only supported for public_page_read")
        if "http_client" in self.capabilities and self.http_action is None:
            raise ValueError("http_client capability requires one HTTP action")
        if self.http_action is not None and self.parameter_digest != http_parameter_digest(
            method=self.http_action.method,
            target=self.normalized_target,
            headers=self.http_action.headers,
        ):
            raise ValueError("HTTP action parameter digest does not match")
        return self


class WorkerResultStatus(StrEnum):
    """Terminal worker outcomes."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    POLICY_DENIED = "policy_denied"
    WORKER_ERROR = "worker_error"


class WorkerHttpCapture(ProtocolModel):
    """One bounded HTTP capture awaiting trusted control-plane persistence."""

    capture_schema: Literal["http-v1"] = "http-v1"
    method: Literal["GET", "HEAD"]
    request_target: str
    request_headers: tuple[tuple[str, str], ...] = Field(default=(), max_length=100)
    status_code: int = Field(ge=100, le=599)
    final_target: str
    response_headers: tuple[tuple[str, str], ...] = Field(default=(), max_length=100)
    body_base64: str = Field(
        max_length=MAXIMUM_INLINE_CAPTURE_BODY_BASE64_CHARACTERS,
        repr=False,
    )
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    captured_at: datetime
    duration_ms: int = Field(ge=0, le=_MAXIMUM_CAPTURE_DURATION_MS)

    @field_validator("request_target", "final_target")
    @classmethod
    def require_canonical_capture_target(cls, value: str) -> str:
        if str(normalize_target(value)) != value:
            raise ValueError("capture targets must use the canonical target format")
        return value

    @field_validator("request_headers")
    @classmethod
    def validate_request_headers(
        cls,
        values: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        return _normalize_worker_headers(values, request=True)

    @field_validator("response_headers")
    @classmethod
    def validate_response_headers(
        cls,
        values: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        return _normalize_worker_headers(values, request=False)

    @model_validator(mode="after")
    def validate_capture_content(self) -> WorkerHttpCapture:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must be timezone-aware")
        if self.final_target != self.request_target:
            raise ValueError("redirected worker captures are not accepted")
        body = self.decoded_body()
        if self.method == "HEAD" and body:
            raise ValueError("HEAD worker captures must not contain a body")
        if hashlib.sha256(body).hexdigest() != self.body_sha256:
            raise ValueError("worker capture body digest does not match")
        return self

    def decoded_body(self) -> bytes:
        """Decode the body only after strict alphabet and decoded-size checks."""
        try:
            body = base64.b64decode(self.body_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("worker capture body is not valid base64") from error
        if len(body) > MAXIMUM_INLINE_CAPTURE_BODY_BYTES:
            raise ValueError("worker capture body exceeds the decoded byte limit")
        return body


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
    http_captures: tuple[WorkerHttpCapture, ...] = Field(default=(), max_length=1, repr=False)
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
        if self.status is WorkerResultStatus.SUCCEEDED:
            if not self.evidence_ids and not self.http_captures:
                raise ValueError("successful responses require evidence_ids or one HTTP capture")
            if self.evidence_ids and self.http_captures:
                raise ValueError("worker responses must not mix evidence_ids and HTTP captures")
            if any(
                capture.captured_at < self.started_at
                or capture.captured_at > self.completed_at
                for capture in self.http_captures
            ):
                raise ValueError("worker capture timestamp is outside the response window")
        elif self.http_captures:
            raise ValueError("non-success responses must not include HTTP captures")
        return self


def _normalize_worker_headers(
    headers: tuple[tuple[str, str], ...],
    *,
    request: bool,
) -> tuple[tuple[str, str], ...]:
    if len(headers) > _MAXIMUM_HTTP_HEADER_COUNT:
        raise ValueError("worker capture header count exceeds limit")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for name, value in headers:
        normalized_name = name.strip().lower()
        normalized_value = value.strip()
        if not normalized_name or not normalized_value:
            raise ValueError("worker capture headers must not be empty")
        if any(character in name or character in value for character in ("\r", "\n", "\0")):
            raise ValueError("worker capture headers contain a forbidden delimiter")
        if request and normalized_name not in _ALLOWED_HTTP_REQUEST_HEADERS:
            raise ValueError("worker capture request header is not allowed")
        if request and normalized_name in seen:
            raise ValueError("worker capture request headers must be unique")
        seen.add(normalized_name)
        total_bytes += len(normalized_name.encode()) + len(normalized_value.encode())
        normalized.append((normalized_name, normalized_value))
    if total_bytes > _MAXIMUM_HTTP_HEADER_BYTES:
        raise ValueError("worker capture headers exceed the byte limit")
    return tuple(sorted(normalized))
