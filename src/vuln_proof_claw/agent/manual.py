"""Record evidence for tests a human performed by hand.

This module does not perform any network operation. It records what a researcher has
already done, so that a finding can be backed by a tamper-evident chain rather than by
a screenshot alone.

Because nothing is executed here, there is no approval gate: an approval authorizes the
system to act, and the system is not acting. Scope is still evaluated, because a
recorded exchange that falls outside the authorized boundary is a problem the
researcher needs to know about immediately.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Final

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.autonomous import Lead, Observation
from vuln_proof_claw.domain.enums import ActionState, ObservationKind
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    EngagementId,
    EvidenceId,
    new_evidence_id,
)
from vuln_proof_claw.domain.models import Action, Flow, Task, utc_now
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.persistence.autonomous_repositories import ObservationRepository
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    FlowRepository,
    TaskRepository,
)
from vuln_proof_claw.policy.risk import classify_risk
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope, normalize_target

MANUAL_TOOL_NAME: Final = "manual-record"
MANUAL_TOOL_VERSION: Final = "v1"
DEFAULT_ACTION_TYPE: Final = "manual_test_record"

_REQUEST_MARKER = re.compile(r"^#{2,3}\s*REQUEST\s*$", re.IGNORECASE | re.MULTILINE)
_RESPONSE_MARKER = re.compile(r"^#{2,3}\s*RESPONSE\s*$", re.IGNORECASE | re.MULTILINE)
_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?\s*$")
_STATUS_LINE = re.compile(r"^HTTP/[\d.]+\s+(?P<status>\d{3})")
_MAX_BODY_BYTES: Final = 256 * 1024
_MIN_HTTP_STATUS: Final = 100
_MAX_HTTP_STATUS: Final = 599


class ManualRecordError(Exception):
    """Raised when a manual exchange cannot be parsed or is out of scope."""


@dataclass(frozen=True, slots=True)
class HttpExchange:
    """One request and response pair observed during manual testing."""

    method: str
    target: str
    status_code: int
    request_headers: tuple[tuple[str, str], ...] = ()
    request_body: str = ""
    response_headers: tuple[tuple[str, str], ...] = ()
    response_body: str = ""

    def __post_init__(self) -> None:
        if not self.method.strip():
            raise DomainValidationError("method must not be empty")
        if not _MIN_HTTP_STATUS <= self.status_code <= _MAX_HTTP_STATUS:
            raise DomainValidationError("status_code must be a valid HTTP status")
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(self, "target", str(normalize_target(self.target)))

    def as_canonical_mapping(self) -> dict[str, object]:
        """Return the stable document that is hashed into the evidence chain."""
        return {
            "schema_version": "v1",
            "kind": "manual_http_exchange",
            "request": {
                "method": self.method,
                "target": self.target,
                "headers": [list(item) for item in self.request_headers],
                "body": self.request_body,
            },
            "response": {
                "status_code": self.status_code,
                "headers": [list(item) for item in self.response_headers],
                "body": self.response_body,
            },
        }


def _split_headers_and_body(block: str) -> tuple[list[str], str]:
    lines = block.replace("\r\n", "\n").split("\n")
    header_lines: list[str] = []
    index = 0
    for index, line in enumerate(lines):  # noqa: B007 - index is used after the loop
        if not line.strip():
            break
        header_lines.append(line)
    else:
        return (header_lines, "")
    return (header_lines, "\n".join(lines[index + 1 :]).strip("\n"))


def _parse_headers(lines: list[str]) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    for line in lines:
        name, separator, value = line.partition(":")
        if not separator:
            continue
        headers.append((name.strip().lower(), value.strip()))
    return tuple(headers)


def parse_exchange(document: str, *, base_url: str | None = None) -> HttpExchange:
    """Parse a request/response transcript pasted from a browser or proxy.

    The expected shape is the one browsers and intercepting proxies produce::

        ### REQUEST
        GET /api/orders/1 HTTP/1.1
        Host: api.example.com

        ### RESPONSE
        HTTP/1.1 200 OK
        Content-Type: application/json

        {"id": 1}
    """
    request_match = _REQUEST_MARKER.search(document)
    response_match = _RESPONSE_MARKER.search(document)
    if request_match is None or response_match is None:
        raise ManualRecordError("transcript must contain '### REQUEST' and '### RESPONSE'")
    if response_match.start() < request_match.end():
        raise ManualRecordError("'### RESPONSE' must follow '### REQUEST'")

    request_block = document[request_match.end() : response_match.start()].strip("\n")
    response_block = document[response_match.end() :].strip("\n")

    request_lines, request_body = _split_headers_and_body(request_block)
    if not request_lines:
        raise ManualRecordError("request block is empty")
    first = _REQUEST_LINE.match(request_lines[0].strip())
    if first is None:
        raise ManualRecordError("first request line must look like 'GET /path HTTP/1.1'")
    request_headers = _parse_headers(request_lines[1:])

    response_lines, response_body = _split_headers_and_body(response_block)
    if not response_lines:
        raise ManualRecordError("response block is empty")
    status = _STATUS_LINE.match(response_lines[0].strip())
    if status is None:
        raise ManualRecordError("first response line must look like 'HTTP/1.1 200 OK'")

    path = first.group("path")
    if path.startswith(("http://", "https://")):
        target = path
    else:
        host = dict(request_headers).get("host")
        origin = base_url or (f"https://{host}" if host else None)
        if origin is None:
            raise ManualRecordError("cannot determine target: add a Host header or pass base_url")
        target = f"{origin.rstrip('/')}{path}"

    for label, body in (("request", request_body), ("response", response_body)):
        if len(body.encode()) > _MAX_BODY_BYTES:
            raise ManualRecordError(f"{label} body exceeds the {_MAX_BODY_BYTES} byte limit")

    return HttpExchange(
        method=first.group("method"),
        target=target,
        status_code=int(status.group("status")),
        request_headers=request_headers,
        request_body=request_body,
        response_headers=_parse_headers(response_lines[1:]),
        response_body=response_body,
    )


@dataclass(frozen=True, slots=True)
class RecordedEvidence:
    """An evidence record plus the exchange it attests to."""

    evidence_id: EvidenceId
    digest: str
    previous_digest: str | None
    exchange: HttpExchange
    scope_reason: str


@dataclass(frozen=True, slots=True)
class RecordedStep:
    """A manual step that produced no capturable HTTP exchange."""

    observation: Observation
    screenshot: Path | None = None
    screenshot_digest: str | None = None


@dataclass
class ManualEvidenceRecorder:
    """Attach hand-performed test evidence to a lead's chain.

    ``engagement_id`` and ``scope`` must come from the stored engagement, not from the
    researcher, so that an out-of-scope exchange cannot be recorded as authorized work.
    """

    session: Session
    engagement_id: EngagementId
    scope: EngagementScope
    actor: str = "researcher"
    action_type: str = DEFAULT_ACTION_TYPE
    _flow_objective: str = field(default="manual verification", init=False)

    def record_exchange(
        self,
        exchange: HttpExchange,
        *,
        at: datetime | None = None,
        allow_out_of_scope: bool = False,
    ) -> RecordedEvidence:
        """Append one manual request/response to the engagement's evidence chain."""
        moment = at or utc_now()
        decision = evaluate_scope(exchange.target, self.scope, at=moment)
        if not decision.allowed and not allow_out_of_scope:
            raise ManualRecordError(
                f"target is outside the authorized scope ({decision.reason}); "
                "recording refused"
            )

        action = self._anchor_action(exchange, at=moment)
        raw = canonical_json(exchange.as_canonical_mapping())
        metadata = EvidenceMetadata(
            evidence_id=new_evidence_id(),
            engagement_id=self.engagement_id,
            action_id=action.id,
            tool_name=MANUAL_TOOL_NAME,
            tool_version=MANUAL_TOOL_VERSION,
            normalized_parameters={
                "method": exchange.method,
                "target": exchange.target,
                "status_code": exchange.status_code,
            },
            captured_at=moment,
            duration_ms=0,
            worker_image="manual",
            environment={"actor": self.actor, "recorded_by": "manual-record"},
            scope_decision=decision.reason,
        )
        record: EvidenceRecord = PersistentEvidenceStore(self.session).append(metadata, raw)
        return RecordedEvidence(
            evidence_id=metadata.evidence_id,
            digest=record.digest,
            previous_digest=record.previous_digest,
            exchange=exchange,
            scope_reason=decision.reason,
        )

    def record_step(
        self,
        lead: Lead,
        summary: str,
        *,
        screenshot: Path | None = None,
        at: datetime | None = None,
    ) -> RecordedStep:
        """Record a manual step that produced no capturable exchange.

        A screenshot is hashed so the report can assert which file it refers to, but
        the image itself stays on disk under the researcher's control.
        """
        if not summary.strip():
            raise ManualRecordError("summary must not be empty")
        moment = at or utc_now()
        digest: str | None = None
        if screenshot is not None:
            if not screenshot.is_file():
                raise ManualRecordError(f"screenshot not found: {screenshot}")
            digest = hashlib.sha256(screenshot.read_bytes()).hexdigest()

        observation = Observation(
            engagement_id=self.engagement_id,
            kind=ObservationKind.HTTP_RESPONSE,
            subject=f"lead:{lead.id}",
            digest=digest or _text_digest(summary),
            summary=summary.strip(),
            observed_at=moment,
        )
        ObservationRepository(self.session).add(observation)
        return RecordedStep(
            observation=observation,
            screenshot=screenshot,
            screenshot_digest=digest,
        )

    def _anchor_action(self, exchange: HttpExchange, *, at: datetime) -> Action:
        """Create the action row the evidence chain attaches to.

        The action is created already completed: a human performed it, the system did
        not, so it never enters the execution queue and never consumes an approval.
        """
        flow = self._ensure_flow(at=at)
        task = Task(flow_id=flow.id, title=f"manual: {exchange.method} {exchange.target}"[:500])
        TaskRepository(self.session).add(task)
        action = Action(
            engagement_id=self.engagement_id,
            task_id=task.id,
            action_type=self.action_type,
            normalized_target=exchange.target,
            parameter_digest=http_parameter_digest(
                method=exchange.method,
                target=exchange.target,
                headers=(),
            ),
            risk_level=classify_risk(self.action_type),
            idempotency_key=f"manual:{at.isoformat()}:{exchange.method}:{exchange.target}",
            state=ActionState.SUCCEEDED,
            created_at=at,
            started_at=at,
            completed_at=at,
        )
        ActionRepository(self.session).add(action)
        self.session.flush()
        return action

    def _ensure_flow(self, *, at: datetime) -> Flow:
        repository = FlowRepository(self.session)
        for stored in repository.list_for_engagement(self.engagement_id, limit=100):
            if stored.entity.objective == self._flow_objective:
                return stored.entity
        flow = Flow(
            engagement_id=self.engagement_id,
            objective=self._flow_objective,
            created_at=at,
        )
        repository.add(flow)
        return flow


def attach_evidence(lead: Lead, evidence_ids: tuple[EvidenceId, ...], *, at: datetime) -> Lead:
    """Return the lead with newly recorded evidence attached, without duplicates."""
    merged = tuple(dict.fromkeys((*lead.evidence_ids, *evidence_ids)))
    return replace(lead, evidence_ids=merged, updated_at=at)


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


__all__ = [
    "DEFAULT_ACTION_TYPE",
    "HttpExchange",
    "ManualEvidenceRecorder",
    "ManualRecordError",
    "RecordedEvidence",
    "RecordedStep",
    "attach_evidence",
    "parse_exchange",
]
