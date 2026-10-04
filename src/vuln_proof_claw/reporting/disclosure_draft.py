"""Render a human-reviewed disclosure draft from verified evidence.

The draft is a starting point for a researcher to review and complete, never a
submission. Two properties matter:

* **Minimal disclosure.** Credentials, cookies, and bearer tokens are redacted from the
  rendered draft. The unredacted exchange stays in the evidence chain, where it can be
  produced on request, rather than being pasted into a document that gets emailed.
* **Verifiability.** Every quoted exchange carries the evidence digest it came from, so
  a reviewer can confirm the quoted text against the tamper-evident chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from vuln_proof_claw.agent.leads import VerificationOutcome
from vuln_proof_claw.agent.manual import HttpExchange
from vuln_proof_claw.config.redaction import is_sensitive_key, redact_text
from vuln_proof_claw.domain.autonomous import Lead
from vuln_proof_claw.domain.enums import FindingSeverity

REDACTED = "[REDACTED]"
_MAX_BODY_CHARACTERS = 4_000

_SEVERITY_BANDS: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "嚴重 (CVSS 9.0-10.0)",
    FindingSeverity.HIGH: "高 (CVSS 7.0-8.9)",
    FindingSeverity.MEDIUM: "中 (CVSS 4.0-6.9)",
    FindingSeverity.LOW: "低 (CVSS 0.1-3.9)",
    FindingSeverity.INFORMATIONAL: "資訊 (待評估)",
}


@dataclass(frozen=True, slots=True)
class DraftExchange:
    """One evidence-backed exchange to include in the draft."""

    exchange: HttpExchange
    evidence_digest: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class DraftStep:
    """One manual reproduction step."""

    summary: str
    screenshot_name: str | None = None
    screenshot_digest: str | None = None


@dataclass(frozen=True, slots=True)
class DisclosureDraft:
    """A rendered draft plus the facts a reviewer still has to supply."""

    content: str
    outstanding: tuple[str, ...]

    @property
    def ready(self) -> bool:
        """Return whether every required field has been supplied."""
        return not self.outstanding


def redact_headers(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Mask credential-bearing headers while keeping their presence visible."""
    return tuple(
        (name, REDACTED if is_sensitive_key(name) else redact_text(value))
        for name, value in headers
    )


def _truncate(body: str) -> str:
    if len(body) <= _MAX_BODY_CHARACTERS:
        return body
    return f"{body[:_MAX_BODY_CHARACTERS]}\n… [截斷，完整內容見證據鏈]"


def render_exchange(entry: DraftExchange) -> str:
    """Render one request/response pair with credentials redacted."""
    exchange = entry.exchange
    lines = ["```http", f"{exchange.method} {exchange.target}"]
    lines.extend(f"{name}: {value}" for name, value in redact_headers(exchange.request_headers))
    if exchange.request_body:
        lines.extend(["", _truncate(redact_text(exchange.request_body))])
    lines.extend(["", f"HTTP {exchange.status_code}"])
    lines.extend(f"{name}: {value}" for name, value in redact_headers(exchange.response_headers))
    if exchange.response_body:
        lines.extend(["", _truncate(redact_text(exchange.response_body))])
    lines.append("```")
    lines.append(f"證據雜湊 (SHA-256): `{entry.evidence_digest}`")
    if entry.note:
        lines.append(f"說明：{entry.note}")
    return "\n".join(lines)


def _outstanding_fields(  # noqa: PLR0913 - one check per required report field
    outcome: VerificationOutcome | None,
    *,
    has_evidence: bool,
    tools_used: tuple[str, ...],
    source_ip: str | None,
    cvss_vector: str | None,
    cvss_score: float | None,
    expected_result: str | None,
    actual_result: str | None,
) -> tuple[str, ...]:
    """List the fields a researcher must still supply before submitting."""
    missing: list[str] = []
    if source_ip is None:
        missing.append("使用 IP（漏洞測試來源 IP）")
    if cvss_score is None or cvss_vector is None:
        missing.append("CVSS v4.0 基礎評分與向量")
    if not has_evidence:
        missing.append("利用步驟與佐證（至少一筆證據或步驟）")
    if outcome is None:
        missing.append("驗證結論（可重現性、是否為預期行為、資安影響）")
    if not tools_used:
        missing.append("使用工具（含 AI 工具）")
    if not expected_result or not actual_result:
        missing.append("預期結果與實際結果")
    return tuple(missing)


def render_draft(  # noqa: PLR0913 - a report section per argument keeps the draft explicit
    lead: Lead,
    outcome: VerificationOutcome | None,
    *,
    program_name: str,
    target_label: str,
    exchanges: tuple[DraftExchange, ...] = (),
    steps: tuple[DraftStep, ...] = (),
    tools_used: tuple[str, ...] = (),
    source_ip: str | None = None,
    cvss_vector: str | None = None,
    cvss_score: float | None = None,
    expected_result: str | None = None,
    actual_result: str | None = None,
    at: datetime | None = None,
) -> DisclosureDraft:
    """Render a disclosure draft in the activity's required section order.

    Fields the researcher must still decide are listed in ``outstanding`` rather than
    being invented, so an incomplete draft cannot be mistaken for a finished report.
    """
    outstanding = _outstanding_fields(
        outcome,
        has_evidence=bool(exchanges or steps),
        tools_used=tools_used,
        source_ip=source_ip,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        expected_result=expected_result,
        actual_result=actual_result,
    )
    severity = outcome.severity if outcome else FindingSeverity.INFORMATIONAL
    moment = at or datetime.now(tz=lead.created_at.tzinfo)

    sections: list[str] = [
        f"# 漏洞通報草稿：{lead.title}",
        "",
        "> 本文件為草稿，必須由研究員逐項確認後才可送出。",
        "> 依活動辦法 5.4.7，僅自動化工具或 AI 工具結果未經實際驗證者不予認定。",
        "",
        "## 基本資料",
        f"- 活動／程式：{program_name}",
        f"- 受測標的：{target_label}",
        f"- 通報時間：{moment.isoformat()}",
        f"- 使用 IP：{source_ip or '【待填】'}",
        "",
        "## 漏洞說明",
        f"- 漏洞類型：{outcome.vulnerability_class if outcome else '【待填】'}",
        f"- 影響標的：{outcome.affected_target if outcome else target_label}",
        f"- 嚴重程度：{_SEVERITY_BANDS[severity]}",
        f"- CVSS v4.0：{cvss_vector or '【待填】'}"
        + (f" （{cvss_score}）" if cvss_score is not None else ""),
        "",
        "### 成因與影響",
        lead.hypothesis,
    ]
    if outcome:
        sections.extend(["", "### 驗證結論", outcome.rationale])

    sections.extend(["", "## 利用步驟"])
    if not steps and not exchanges:
        sections.append("【待填】請補充可重現的操作步驟。")
    for index, step in enumerate(steps, start=1):
        line = f"{index}. {step.summary}"
        if step.screenshot_name:
            line += f"\n   - 截圖：`{step.screenshot_name}`"
            if step.screenshot_digest:
                line += f"（SHA-256 `{step.screenshot_digest}`）"
        sections.append(line)

    if exchanges:
        sections.extend(["", "## 佐證（HTTP 交換紀錄）", ""])
        sections.append("> 憑證、Cookie 與授權標頭已遮蔽；完整內容保存於證據鏈，可應要求提供。")
        for index, entry in enumerate(exchanges, start=1):
            sections.extend(["", f"### 佐證 {index}", render_exchange(entry)])

    sections.extend(
        [
            "",
            "## 預期結果與實際結果",
            f"- 預期：{expected_result or '【待填】'}",
            f"- 實際：{actual_result or '【待填】'}",
            "",
            "## 修補建議",
            outcome.remediation if outcome else "【待填】",
            "",
            "## 使用工具（含 AI 工具）",
        ]
    )
    if tools_used:
        sections.extend(f"- {tool}" for tool in tools_used)
    else:
        sections.append("【待填】依活動辦法 5.4.1，使用 AI 工具必須於此欄載明。")

    sections.extend(
        [
            "",
            "## 證據鏈",
            f"- 證據筆數：{len(exchanges)}",
            f"- Lead 識別碼：`{lead.id}`",
        ]
    )
    if lead.evidence_ids:
        sections.append(f"- 證據識別碼：{', '.join(f'`{item}`' for item in lead.evidence_ids)}")

    if outstanding:
        sections.extend(["", "## ⚠ 尚待補齊"])
        sections.extend(f"- {item}" for item in outstanding)

    return DisclosureDraft(content="\n".join(sections) + "\n", outstanding=outstanding)


__all__ = [
    "DisclosureDraft",
    "DraftExchange",
    "DraftStep",
    "redact_headers",
    "render_draft",
    "render_exchange",
]
