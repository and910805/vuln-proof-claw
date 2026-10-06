"""Tests for carrying a query string without widening authorization.

The query is deliberately kept out of the normalized target: scope decides from scheme,
host, port, and path, and a query must not be able to move that boundary. But the query
does change what a request asks for, so it is bound into the parameter digest.

These tests pin both halves of that: the query reaches the wire, and it cannot be
swapped under an approval that covered a different one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId, TaskId
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.execution.http_capture import (
    HttpCaptureRequest,
    HttpCaptureResponse,
    capture_parameter_digest,
    http_capture_evidence_bytes,
)
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope, normalize_query

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
ACTION = ActionId("01a10702-68f9-7918-b91b-ba7656f04545")
TARGET = "https://api.example.com:443/api/getCompanyDisplay"
DIGEST = "a" * 64


def test_an_empty_query_produces_the_pre_existing_digest() -> None:
    """Backward compatibility: every stored action and issued approval stays valid."""
    without = http_parameter_digest(method="GET", target=TARGET, headers=())
    explicit = http_parameter_digest(method="GET", target=TARGET, headers=(), query="")

    assert without == explicit


def test_a_query_changes_the_digest() -> None:
    plain = http_parameter_digest(method="GET", target=TARGET, headers=())
    with_query = http_parameter_digest(
        method="GET", target=TARGET, headers=(), query="adminUuid=abc"
    )

    assert plain != with_query


def test_two_different_queries_do_not_share_a_digest() -> None:
    """Approving one query must not approve another against the same path."""
    first = http_parameter_digest(method="GET", target=TARGET, headers=(), query="id=1")
    second = http_parameter_digest(method="GET", target=TARGET, headers=(), query="id=2")

    assert first != second


def test_an_inline_query_is_split_off_the_target() -> None:
    request = HttpCaptureRequest(
        action_id=ACTION,
        method="GET",
        target=f"{TARGET}?adminUuid=1111",
    )

    assert request.target == TARGET
    assert request.query == "adminUuid=1111"


def test_an_explicit_query_is_accepted() -> None:
    request = HttpCaptureRequest(
        action_id=ACTION, method="GET", target=TARGET, query="adminUuid=1111"
    )

    assert request.query == "adminUuid=1111"


def test_supplying_a_query_twice_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="both inline and explicitly"):
        HttpCaptureRequest(
            action_id=ACTION,
            method="GET",
            target=f"{TARGET}?a=1",
            query="b=2",
        )


def test_the_capture_digest_covers_the_query() -> None:
    plain = capture_parameter_digest(
        HttpCaptureRequest(action_id=ACTION, method="GET", target=TARGET)
    )
    with_query = capture_parameter_digest(
        HttpCaptureRequest(action_id=ACTION, method="GET", target=f"{TARGET}?id=1")
    )

    assert plain != with_query


def test_a_query_cannot_move_the_scope_decision() -> None:
    """A query must never make an out-of-scope host reachable, or vice versa."""
    scope = EngagementScope.create(
        allowed_hostnames=("api.example.com",),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        allowed_paths=("/api",),
    )

    allowed = evaluate_scope(f"{TARGET}?adminUuid=1", scope, at=NOW)
    denied = evaluate_scope("https://attacker.test:443/api/x?adminUuid=1", scope, at=NOW)
    wrong_path = evaluate_scope("https://api.example.com:443/admin?x=1", scope, at=NOW)

    assert allowed.allowed
    assert str(allowed.target) == TARGET  # the query is not part of the decision
    assert not denied.allowed
    assert not wrong_path.allowed


@pytest.mark.parametrize(
    "value",
    [
        "a=1\r\nHost: evil.test",
        "a=1\nX-Injected: 1",
        "a=\x00b",
        "a=%zz",
        "a=" + "x" * 5000,
    ],
)
def test_a_crafted_query_is_refused(value: str) -> None:
    """A query reaches the request line; smuggling must be impossible."""
    with pytest.raises(DomainValidationError):
        normalize_query(value)


def test_an_empty_query_normalises_to_empty() -> None:
    assert normalize_query("") == ""


def test_a_query_is_re_encoded_rather_than_passed_through() -> None:
    assert normalize_query("a=hello world") == "a=hello+world"
    assert normalize_query("a=1&b=two") == "a=1&b=two"


def test_a_query_with_no_pairs_is_refused() -> None:
    with pytest.raises(DomainValidationError):
        normalize_query("&&&")


def make_action(query: str = "") -> Action:
    return Action(
        engagement_id=EngagementId("e"),
        task_id=TaskId("t"),
        action_type="public_page_read",
        normalized_target=TARGET,
        parameter_digest=DIGEST,
        risk_level=RiskLevel.L0,
        idempotency_key="k",
        query=query,
        state=ActionState.PROPOSED,
        created_at=NOW,
    )


def test_an_action_carries_its_query() -> None:
    assert make_action("adminUuid=1").query == "adminUuid=1"
    assert make_action().query == ""


@pytest.mark.parametrize("value", ["a=1?b=2", "a=1#frag", "a=1\r\nx: y", "a=1\nx"])
def test_an_action_refuses_a_delimiter_in_its_query(value: str) -> None:
    with pytest.raises(DomainValidationError, match="delimiter or line break"):
        make_action(value)


def test_the_evidence_document_records_the_query() -> None:
    """A reviewer must be able to reproduce the request from the evidence alone."""
    response = HttpCaptureResponse(
        status_code=500,
        final_target=TARGET,
        headers=(("content-type", "application/json"),),
        body=b'{"Status":"Error"}',
        duration_ms=10,
    )
    document = json.loads(
        http_capture_evidence_bytes(
            HttpCaptureRequest(
                action_id=ACTION, method="GET", target=f"{TARGET}?adminUuid=1111"
            ),
            response,
        )
    )

    assert document["request"]["query"] == "adminUuid=1111"
    assert document["request"]["target"] == TARGET


def test_an_evidence_document_without_a_query_is_unchanged() -> None:
    """Captures without a query must keep hashing to the document they always did."""
    response = HttpCaptureResponse(
        status_code=200,
        final_target=TARGET,
        headers=(),
        body=b"ok",
        duration_ms=1,
    )
    document = json.loads(
        http_capture_evidence_bytes(
            HttpCaptureRequest(action_id=ACTION, method="GET", target=TARGET), response
        )
    )

    assert "query" not in document["request"]
