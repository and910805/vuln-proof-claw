"""Tests for rendering a disclosure draft from verified evidence."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vuln_proof_claw.agent.leads import VerificationOutcome
from vuln_proof_claw.agent.manual import HttpExchange
from vuln_proof_claw.domain.autonomous import Lead
from vuln_proof_claw.domain.enums import FindingSeverity, VerificationMethod
from vuln_proof_claw.domain.identifiers import (
    EvidenceId,
    new_engagement_id,
    new_mission_id,
)
from vuln_proof_claw.reporting.disclosure_draft import (
    DraftExchange,
    DraftStep,
    redact_headers,
    render_draft,
    render_exchange,
)

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
DIGEST = "c" * 64
SECRET_COOKIE = "session=super-secret-value"  # noqa: S105 - test credential
SECRET_TOKEN = "Bearer abcdef123456"  # noqa: S105 - test credential


def make_lead(**overrides: object) -> Lead:
    defaults: dict[str, object] = {
        "engagement_id": new_engagement_id(),
        "mission_id": new_mission_id(),
        "title": "訂單物件缺乏擁有者檢查",
        "hypothesis": "訂單端點未驗證請求者是否為該物件擁有者。",
        "category": "broken_object_level_authorization",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Lead(**defaults)  # type: ignore[arg-type]


def make_exchange() -> HttpExchange:
    return HttpExchange(
        method="GET",
        target="https://api.example.com:443/orders/1",
        status_code=200,
        request_headers=(
            ("host", "api.example.com"),
            ("cookie", SECRET_COOKIE),
            ("authorization", SECRET_TOKEN),
            ("accept", "application/json"),
        ),
        response_headers=(
            ("content-type", "application/json"),
            ("set-cookie", "session=rotated"),
        ),
        response_body='{"id": 1, "owner": "another-user"}',
    )


def make_outcome(**overrides: object) -> VerificationOutcome:
    defaults: dict[str, object] = {
        "reproducible": True,
        "expected_behavior": False,
        "proves_security_impact": True,
        "requires_destructive_testing": False,
        "vulnerability_class": "不安全之物件參照",
        "affected_target": "https://api.example.com/orders/{id}",
        "rationale": "以 user_b 的工作階段取得 user_a 的訂單內容。",
        "evidence_ids": (EvidenceId("11111111-1111-7111-8111-111111111111"),),
        "severity": FindingSeverity.HIGH,
        "remediation": "在查詢訂單時比對工作階段主體與訂單擁有者。",
        # The rationale describes one identity's session reaching another's order, so
        # the method is a comparison, and the control is the response it was measured
        # against. At this severity both have to be stated.
        "verification_method": VerificationMethod.DIFFERENTIAL,
        "control_evidence_ids": (EvidenceId("22222222-2222-7222-8222-222222222222"),),
    }
    defaults.update(overrides)
    return VerificationOutcome(**defaults)  # type: ignore[arg-type]


def test_credential_headers_are_redacted_but_remain_visible() -> None:
    redacted = dict(redact_headers(make_exchange().request_headers))

    assert redacted["cookie"] == "[REDACTED]"
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["host"] == "api.example.com"
    assert redacted["accept"] == "application/json"


def test_a_rendered_exchange_never_contains_the_secret() -> None:
    rendered = render_exchange(DraftExchange(exchange=make_exchange(), evidence_digest=DIGEST))

    assert "super-secret-value" not in rendered
    assert "abcdef123456" not in rendered
    assert "another-user" in rendered
    assert DIGEST in rendered


def test_a_complete_draft_is_marked_ready() -> None:
    draft = render_draft(
        make_lead(),
        make_outcome(),
        program_name="產品資安升級行動",
        target_label="IT-99 範例系統",
        exchanges=(DraftExchange(exchange=make_exchange(), evidence_digest=DIGEST),),
        steps=(DraftStep(summary="以 user_b 登入"),),
        tools_used=("Burp Suite", "Claude Code（分析與文件整理）"),
        source_ip="203.0.113.10",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N",
        cvss_score=7.1,
        expected_result="應回傳 403",
        actual_result="回傳他人資料",
        at=NOW,
    )

    assert draft.ready
    assert draft.outstanding == ()
    assert "不安全之物件參照" in draft.content
    assert "高 (CVSS 7.0-8.9)" in draft.content


def test_a_draft_is_not_ready_while_the_document_still_says_todo() -> None:
    """A draft that renders 【待填】 must never report itself as complete."""
    draft = render_draft(
        make_lead(),
        make_outcome(),
        program_name="X",
        target_label="Y",
        exchanges=(DraftExchange(exchange=make_exchange(), evidence_digest=DIGEST),),
        tools_used=("Burp",),
        source_ip="203.0.113.10",
        cvss_vector="CVSS:4.0/AV:N",
        cvss_score=7.1,
        at=NOW,
    )

    assert "【待填】" in draft.content
    assert not draft.ready
    assert "預期結果與實際結果" in draft.outstanding


def test_supplying_expected_and_actual_completes_the_draft() -> None:
    draft = render_draft(
        make_lead(),
        make_outcome(),
        program_name="X",
        target_label="Y",
        exchanges=(DraftExchange(exchange=make_exchange(), evidence_digest=DIGEST),),
        tools_used=("Burp",),
        source_ip="203.0.113.10",
        cvss_vector="CVSS:4.0/AV:N",
        cvss_score=7.1,
        expected_result="應回傳 403 或僅回傳自身資料",
        actual_result="回傳其他使用者的帳號、角色與電子郵件",
        at=NOW,
    )

    assert draft.ready
    assert "【待填】" not in draft.content


def test_an_incomplete_draft_lists_what_is_missing_instead_of_inventing_it() -> None:
    draft = render_draft(
        make_lead(),
        None,
        program_name="產品資安升級行動",
        target_label="IT-99 範例系統",
        at=NOW,
    )

    assert not draft.ready
    assert "使用 IP（漏洞測試來源 IP）" in draft.outstanding
    assert "CVSS v4.0 基礎評分與向量" in draft.outstanding
    assert "驗證結論（可重現性、是否為預期行為、資安影響）" in draft.outstanding
    assert "使用工具（含 AI 工具）" in draft.outstanding
    assert "尚待補齊" in draft.content


def test_the_draft_requires_ai_tools_to_be_declared() -> None:
    """活動辦法 5.4.1 makes the tools field mandatory when AI assisted."""
    draft = render_draft(
        make_lead(),
        make_outcome(),
        program_name="產品資安升級行動",
        target_label="IT-99",
        exchanges=(DraftExchange(exchange=make_exchange(), evidence_digest=DIGEST),),
        source_ip="203.0.113.10",
        cvss_vector="CVSS:4.0/AV:N",
        cvss_score=7.1,
        at=NOW,
    )

    assert "使用工具（含 AI 工具）" in draft.outstanding
    assert "必須於此欄載明" in draft.content


def test_the_draft_states_that_it_is_not_a_submission() -> None:
    draft = render_draft(
        make_lead(), None, program_name="X", target_label="Y", at=NOW
    )

    assert "草稿" in draft.content
    assert "5.4.7" in draft.content


def test_a_screenshot_digest_is_carried_into_the_steps() -> None:
    draft = render_draft(
        make_lead(),
        make_outcome(),
        program_name="X",
        target_label="Y",
        steps=(
            DraftStep(summary="開啟訂單頁", screenshot_name="01.png", screenshot_digest=DIGEST),
        ),
        tools_used=("Burp",),
        source_ip="203.0.113.10",
        cvss_vector="CVSS:4.0/AV:N",
        cvss_score=7.1,
        at=NOW,
    )

    assert "01.png" in draft.content
    assert DIGEST in draft.content


@pytest.mark.parametrize(
    ("severity", "band"),
    [
        (FindingSeverity.CRITICAL, "嚴重 (CVSS 9.0-10.0)"),
        (FindingSeverity.HIGH, "高 (CVSS 7.0-8.9)"),
        (FindingSeverity.MEDIUM, "中 (CVSS 4.0-6.9)"),
        (FindingSeverity.LOW, "低 (CVSS 0.1-3.9)"),
    ],
)
def test_severity_maps_to_the_activity_bounty_bands(
    severity: FindingSeverity, band: str
) -> None:
    draft = render_draft(
        make_lead(),
        make_outcome(severity=severity),
        program_name="X",
        target_label="Y",
        at=NOW,
    )

    assert band in draft.content


def test_a_long_body_is_truncated_with_a_pointer_to_the_chain() -> None:
    exchange = HttpExchange(
        method="GET",
        target="https://api.example.com:443/dump",
        status_code=200,
        response_body="x" * 5_000,
    )

    rendered = render_exchange(DraftExchange(exchange=exchange, evidence_digest=DIGEST))

    assert "截斷" in rendered
    assert len(rendered) < 5_000


def test_the_draft_renders_the_full_request_line_with_its_query() -> None:
    """A reviewer must be able to replay exactly what was sent."""
    exchange = HttpExchange(
        method="GET",
        target="https://api.example.com:443/api/getCompanyDisplay",
        status_code=500,
        query="adminUuid=1111",
        response_body='{"ErrorMessage":"adminUuid is not existing"}',
    )

    rendered = render_exchange(DraftExchange(exchange=exchange, evidence_digest=DIGEST))

    assert "GET https://api.example.com:443/api/getCompanyDisplay?adminUuid=1111" in rendered
