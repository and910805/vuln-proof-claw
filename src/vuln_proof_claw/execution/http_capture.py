"""Fail-closed orchestration for structured GET/HEAD HTTP evidence capture."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import ActionId, EvidenceId, new_evidence_id
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.authorization import (
    ExecutionAuthorizationError,
    authorize_queued_action,
    begin_execution,
)
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.persistence.repositories import ActionRepository
from vuln_proof_claw.policy.scope import normalize_query, normalize_target

_ALLOWED_METHODS = frozenset({"GET", "HEAD"})
_ALLOWED_REQUEST_HEADERS = frozenset({"accept", "user-agent"})
_MAX_HEADER_COUNT = 100
_MAX_HEADER_BYTES = 64 * 1024
_MAX_TIMEOUT_SECONDS = 60
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_HEADER_PAIR_SIZE = 2


class HttpCaptureError(Exception):
    """Base class for safe, expected capture failures."""


class CapturePolicyError(HttpCaptureError):
    """Raised when an action or request fails a control-plane invariant."""


class CaptureTransportError(HttpCaptureError):
    """Raised when the isolated transport cannot complete a request."""


class InvalidHttpCaptureEvidenceError(HttpCaptureError):
    """Stored bytes are not a canonical, self-consistent http-v1 capture document."""


@dataclass(frozen=True, slots=True)
class HttpCaptureRequest:
    """Protected request parameters bound to an existing queued Action."""

    action_id: ActionId
    method: Literal["GET", "HEAD"]
    target: str
    headers: tuple[tuple[str, str], ...] = ()
    query: str = ""

    def __post_init__(self) -> None:
        """Split the query from the target.

        ``target`` stays query-free because that is what scope evaluates and what an
        approval binds a host and path to. The query travels alongside it and is folded
        into the parameter digest, so it cannot widen authorization but also cannot be
        swapped silently. A query given inline in ``target`` is accepted and moved.
        """
        method = self.method.upper()
        if method not in _ALLOWED_METHODS:
            raise DomainValidationError("HTTP capture only supports GET and HEAD")
        inline = urlsplit(self.target).query
        if inline and self.query:
            raise DomainValidationError("query supplied both inline and explicitly")
        normalized_target = str(normalize_target(self.target))
        normalized_headers = _normalize_headers(self.headers, request=True)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "target", normalized_target)
        object.__setattr__(self, "headers", normalized_headers)
        object.__setattr__(self, "query", normalize_query(inline or self.query))


@dataclass(frozen=True, slots=True)
class HttpCaptureLimits:
    timeout_seconds: int = 10
    max_response_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise DomainValidationError("capture timeout must be between 1 and 60 seconds")
        if not 1 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES:
            raise DomainValidationError("capture response limit must be between 1 byte and 10 MiB")


@dataclass(frozen=True, slots=True)
class HttpCaptureResponse:
    """Bounded response returned by a scope-enforcing isolated transport."""

    status_code: int
    final_target: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    duration_ms: int

    def __post_init__(self) -> None:
        if not _MIN_HTTP_STATUS <= self.status_code <= _MAX_HTTP_STATUS:
            raise DomainValidationError("HTTP status code is invalid")
        if self.duration_ms < 0:
            raise DomainValidationError("capture duration must not be negative")
        object.__setattr__(self, "final_target", str(normalize_target(self.final_target)))
        object.__setattr__(self, "headers", _normalize_headers(self.headers, request=False))
        object.__setattr__(self, "body", bytes(self.body))


@dataclass(frozen=True, slots=True)
class ParsedHttpCapture:
    """Typed request and response reconstructed from one stored capture document."""

    request: HttpCaptureRequest
    response: HttpCaptureResponse


class HttpCaptureTransport(Protocol):
    """Network boundary; implementations must pin DNS and enforce scope internally."""

    @property
    def identity(self) -> str:
        """Return an immutable transport/image identity for evidence metadata."""

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        """Send without redirects and return a bounded response."""


@dataclass(frozen=True, slots=True)
class HttpCaptureResult:
    evidence: EvidenceRecord | None
    action_state: ActionState
    error_code: str | None = None
    response: HttpCaptureResponse | None = None

    def __post_init__(self) -> None:
        if self.action_state is ActionState.SUCCEEDED and self.evidence is None:
            raise DomainValidationError("successful capture requires evidence")
        if self.action_state is ActionState.SUCCEEDED and self.error_code is not None:
            raise DomainValidationError("successful capture must not have an error code")
        if self.action_state is ActionState.SUCCEEDED and self.response is None:
            raise DomainValidationError("successful capture requires a response")
        if self.action_state is not ActionState.SUCCEEDED and self.error_code is None:
            raise DomainValidationError("failed capture requires an error code")
        if self.action_state is not ActionState.SUCCEEDED and self.response is not None:
            raise DomainValidationError("failed capture must not expose a response")


def _normalize_headers(
    headers: tuple[tuple[str, str], ...],
    *,
    request: bool,
) -> tuple[tuple[str, str], ...]:
    if len(headers) > _MAX_HEADER_COUNT:
        raise DomainValidationError("HTTP header count exceeds limit")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for name, value in headers:
        normalized_name = name.strip().lower()
        normalized_value = value.strip()
        if not normalized_name or not normalized_value:
            raise DomainValidationError("HTTP header name and value must not be empty")
        if any(character in name or character in value for character in ("\r", "\n", "\x00")):
            raise DomainValidationError("HTTP headers must not contain control delimiters")
        if request and normalized_name not in _ALLOWED_REQUEST_HEADERS:
            raise DomainValidationError(f"request header is not allowed: {normalized_name}")
        if request and normalized_name in seen:
            raise DomainValidationError(f"duplicate HTTP header: {normalized_name}")
        seen.add(normalized_name)
        total_bytes += len(normalized_name.encode()) + len(normalized_value.encode())
        normalized.append((normalized_name, normalized_value))
    if total_bytes > _MAX_HEADER_BYTES:
        raise DomainValidationError("HTTP headers exceed byte limit")
    return tuple(sorted(normalized))


def capture_parameter_digest(request: HttpCaptureRequest) -> str:
    """Bind an Action to the exact method, target, query, and safe request headers."""
    return http_parameter_digest(
        method=request.method,
        target=request.target,
        headers=request.headers,
        query=request.query,
    )


def http_capture_evidence_bytes(
    request: HttpCaptureRequest,
    response: HttpCaptureResponse,
) -> bytes:
    """Build the canonical document that is hashed into the evidence chain.

    The query is recorded whenever one was sent, because a reviewer must be able to
    reproduce the exact request from the evidence alone. It is omitted when empty so
    that a capture without a query hashes to the same document it always did.
    """
    recorded_request: dict[str, object] = {
        "headers": [list(item) for item in request.headers],
        "method": request.method,
        "target": request.target,
    }
    if request.query:
        recorded_request["query"] = request.query
    return canonical_json(
        {
            "capture_schema": "http-v1",
            "request": recorded_request,
            "response": {
                "body_base64": base64.b64encode(response.body).decode("ascii"),
                "body_sha256": hashlib.sha256(response.body).hexdigest(),
                "final_target": response.final_target,
                "headers": [list(item) for item in response.headers],
                "status_code": response.status_code,
            },
        }
    )


def _capture_object(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise InvalidHttpCaptureEvidenceError("http_capture_schema_invalid")
    return cast("dict[str, object]", value)


def _capture_headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise InvalidHttpCaptureEvidenceError("http_capture_headers_invalid")
    headers: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != _HEADER_PAIR_SIZE
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise InvalidHttpCaptureEvidenceError("http_capture_headers_invalid")
        headers.append((item[0], item[1]))
    return tuple(headers)


def parse_http_capture_evidence(raw: bytes, *, action_id: ActionId) -> ParsedHttpCapture:
    """Reconstruct the exact producer document; never trust caller-supplied observations.

    The action ID is supplied by the evidence index, since it is not part of the raw
    HTTP document. The caller must still verify that index, Action, scope and approval.
    Duration is metadata outside this document, so the reconstructed response uses 0.
    """
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise InvalidHttpCaptureEvidenceError("http_capture_evidence_too_large")
    try:
        document: object = json.loads(raw)
        if canonical_json(document) != raw:
            raise InvalidHttpCaptureEvidenceError("http_capture_not_canonical")
        root = _capture_object(
            document, required=frozenset({"capture_schema", "request", "response"})
        )
        if root["capture_schema"] != "http-v1":
            raise InvalidHttpCaptureEvidenceError("http_capture_schema_invalid")
        request_data = _capture_object(
            root["request"],
            required=frozenset({"headers", "method", "target"}),
            optional=frozenset({"query"}),
        )
        response_data = _capture_object(
            root["response"],
            required=frozenset(
                {"body_base64", "body_sha256", "final_target", "headers", "status_code"}
            ),
        )
        method = request_data["method"]
        target = request_data["target"]
        query = request_data.get("query", "")
        final_target = response_data["final_target"]
        status_code = response_data["status_code"]
        encoded_body = response_data["body_base64"]
        body_sha256 = response_data["body_sha256"]
        if (
            not isinstance(method, str)
            or method not in _ALLOWED_METHODS
            or not isinstance(target, str)
            or not isinstance(query, str)
            or not isinstance(final_target, str)
            or not isinstance(status_code, int)
            or isinstance(status_code, bool)
            or not isinstance(encoded_body, str)
            or not isinstance(body_sha256, str)
        ):
            raise InvalidHttpCaptureEvidenceError("http_capture_fields_invalid")
        request = HttpCaptureRequest(
            action_id=action_id,
            method=cast('Literal["GET", "HEAD"]', method),
            target=target,
            headers=_capture_headers(request_data["headers"]),
            query=query,
        )
        body = base64.b64decode(encoded_body, validate=True)
        if len(body) > _MAX_RESPONSE_BYTES or hashlib.sha256(body).hexdigest() != body_sha256:
            raise InvalidHttpCaptureEvidenceError("http_capture_body_invalid")
        response = HttpCaptureResponse(
            status_code=status_code,
            final_target=final_target,
            headers=_capture_headers(response_data["headers"]),
            body=body,
            duration_ms=0,
        )
        if (
            response.final_target != request.target
            or http_capture_evidence_bytes(request, response) != raw
        ):
            raise InvalidHttpCaptureEvidenceError("http_capture_content_mismatch")
        return ParsedHttpCapture(request=request, response=response)
    except (ValueError, UnicodeDecodeError, DomainValidationError, RecursionError) as error:
        raise InvalidHttpCaptureEvidenceError("http_capture_evidence_invalid") from error


class HttpCaptureCoordinator:
    """Authorize, execute through an injected boundary, and persist one capture."""

    def __init__(self, session: Session, transport: HttpCaptureTransport) -> None:
        self._session = session
        self._transport = transport

    def capture(
        self,
        request: HttpCaptureRequest,
        *,
        limits: HttpCaptureLimits | None = None,
        at: datetime | None = None,
        evidence_id: EvidenceId | None = None,
    ) -> HttpCaptureResult:
        timestamp = (at or datetime.now(UTC)).astimezone(UTC)
        capture_limits = limits or HttpCaptureLimits()
        action_repository = ActionRepository(self._session)
        stored_action = action_repository.get(request.action_id)
        if stored_action is None:
            raise CapturePolicyError("action_not_found")
        action = stored_action.entity
        if action.normalized_target != request.target:
            raise CapturePolicyError("target_mismatch")
        if action.parameter_digest != capture_parameter_digest(request):
            raise CapturePolicyError("parameter_digest_mismatch")

        try:
            authorization = authorize_queued_action(
                self._session,
                stored_action,
                at=timestamp,
            )
        except ExecutionAuthorizationError as error:
            raise CapturePolicyError(str(error)) from error
        decision = authorization.decision
        running_stored = begin_execution(self._session, authorization, at=timestamp)
        try:
            response = self._transport.send(request, capture_limits)
            if response.final_target != request.target:
                raise CaptureTransportError("redirect_or_target_change_rejected")
            if len(response.body) > capture_limits.max_response_bytes:
                raise CaptureTransportError("response_body_too_large")
            if request.method == "HEAD" and response.body:
                raise CaptureTransportError("head_response_body_rejected")
        except Exception as error:  # noqa: BLE001 - arbitrary transports fail closed
            failed = transition_action(running_stored.entity, ActionState.FAILED, at=timestamp)
            saved_failure = action_repository.save(failed, expected_version=running_stored.version)
            error_code = str(error) if isinstance(error, HttpCaptureError) else "transport_failure"
            return HttpCaptureResult(
                evidence=None,
                action_state=saved_failure.entity.state,
                error_code=error_code,
            )

        raw_content = http_capture_evidence_bytes(request, response)
        item_id = evidence_id or new_evidence_id()
        metadata = EvidenceMetadata(
            evidence_id=item_id,
            engagement_id=action.engagement_id,
            action_id=action.id,
            tool_name="http-capture",
            tool_version="v1",
            normalized_parameters={
                "headers": [list(item) for item in request.headers],
                "method": request.method,
                "target": request.target,
                **({"query": request.query} if request.query else {}),
            },
            captured_at=timestamp,
            duration_ms=response.duration_ms,
            worker_image=self._transport.identity,
            environment={"redirects": "disabled", "transport": "injected"},
            scope_decision=decision.reason,
            approval_id=action.approval_id,
            media_type="application/vnd.vuln-proof-claw.http-capture+json",
        )
        evidence = PersistentEvidenceStore(self._session).append(metadata, raw_content)
        succeeded = transition_action(running_stored.entity, ActionState.SUCCEEDED, at=timestamp)
        saved = action_repository.save(succeeded, expected_version=running_stored.version)
        return HttpCaptureResult(
            evidence=evidence,
            action_state=saved.entity.state,
            response=response,
        )
