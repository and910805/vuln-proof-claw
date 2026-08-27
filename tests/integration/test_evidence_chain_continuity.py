"""The shipped bundle's hash chain must cover exactly the evidence a real flow produced.

Every leg of this chain has unit coverage. What has none is the hand-off: the report
route orders evidence by ``captured_at`` while the store appends it by ``chain_index``,
the bundle builder copies whatever the report handed it into ``manifest.json``, and the
offline verifier only ever sees the manifest. A manifest that agrees with itself but not
with the store would satisfy every existing test, so these tests recompute the digests
from the persisted canonical metadata and raw bytes and compare those against the bytes
that actually shipped.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.test_approvals import OPERATOR_HEADERS
from tests.api.test_assessments import FakeAssessmentTransport, assessment_client
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.finding import requires_control_evidence, review_finding
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId, FindingId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.evidence.hash_chain import compute_digest
from vuln_proof_claw.persistence.models import EvidencePayloadRecord, EvidenceRecord
from vuln_proof_claw.persistence.repositories import FindingRepository
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.reporting.bundle import MANIFEST_NAME, verify_disclosure_bundle

_ASSESSED_PATHS = ("/v1", "/v1/users", "/v1/orders")
_EXPECTED_LINKS = len(_ASSESSED_PATHS)
_MINIMUM_CONTROL_RECORDS = 2
_FABRICATED_DIGEST = "c" * 64
_REPOINTED_DIGEST = "0" * 64


@contextmanager
def _direct_session(database_path: Path) -> Iterator[Session]:
    """Open the same SQLite file the ASGI app just wrote, for read-back only."""
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            yield session
    finally:
        engine.dispose()


async def _drive_three_assessments(client: AsyncClient) -> tuple[str, tuple[str, ...]]:
    """Run three passive assessments in one engagement so the chain has real links.

    ``AssessmentSummary.evidence_ids`` is engagement-scoped, not per-action: each reply
    lists every assessment evidence record the engagement holds so far. That makes each
    reply a snapshot of the caller-visible chain, so this asserts every snapshot extends
    the previous one by appending only, and returns the final snapshot -- the API's own
    statement of what the flow captured, which the shipped chain has to be exactly.
    """
    engagement_id = await _create_engagement(client)
    reported: tuple[str, ...] = ()
    for index, path in enumerate(_ASSESSED_PATHS):
        response = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": f"https://api.example.test{path}"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": f"chain-leg-{index}"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["state"] == "succeeded"
        snapshot = tuple(response.json()["evidence_ids"])
        assert snapshot[: len(reported)] == reported, "evidence must only ever be appended"
        assert len(snapshot) > len(reported), "each assessment must capture evidence"
        reported = snapshot
    assert len(reported) >= _EXPECTED_LINKS, "the chain needs more than a genesis entry"
    return engagement_id, reported


async def _download_bundle(client: AsyncClient, engagement_id: str) -> bytes:
    response = await client.get(
        f"/api/v1/engagements/{engagement_id}/report.bundle.zip",
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    return response.content


def _recomputed_chain(database_path: Path) -> tuple[tuple[str, str | None, str], ...]:
    """Rebuild ``(evidence_id, previous_digest, digest)`` from the store's own bytes.

    The previous digest fed into each link is this function's own running value, not the
    ``previous_digest`` column, so the result is an independent reconstruction of the
    chain rather than a restatement of what the store claims the chain is.
    """
    with _direct_session(database_path) as session:
        rows = session.execute(
            select(EvidencePayloadRecord, EvidenceRecord)
            .join(EvidenceRecord, EvidenceRecord.id == EvidencePayloadRecord.evidence_id)
            .order_by(EvidencePayloadRecord.chain_index)
        ).all()
        chain: list[tuple[str, str | None, str]] = []
        previous: str | None = None
        for payload, metadata in rows:
            digest = compute_digest(
                previous_digest=previous,
                canonical_metadata=bytes(payload.canonical_metadata),
                raw_content=bytes(payload.raw_content),
            )
            chain.append((str(metadata.id), previous, digest))
            previous = digest
        return tuple(chain)


def _read_member(archive_bytes: bytes, name: str) -> bytes:
    with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
        return archive.read(name)


def _manifest(archive_bytes: bytes) -> dict[str, Any]:
    loaded = json.loads(_read_member(archive_bytes, MANIFEST_NAME))
    assert isinstance(loaded, dict)
    return loaded


def _encode_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _repack(archive_bytes: bytes, overrides: dict[str, bytes]) -> bytes:
    """Rewrite the archive with the named members replaced, leaving the rest untouched."""
    output = BytesIO()
    with zipfile.ZipFile(BytesIO(archive_bytes)) as source, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED
    ) as target:
        for name in source.namelist():
            target.writestr(name, overrides.get(name, source.read(name)))
    return output.getvalue()


def _tampered_copy(
    tmp_path: Path,
    original: bytes,
    name: str,
    overrides: dict[str, bytes],
) -> Path:
    path = tmp_path / f"{name}.zip"
    path.write_bytes(_repack(original, overrides))
    return path


async def test_shipped_bundle_chain_is_exactly_the_stored_chain(tmp_path: Path) -> None:
    database_path = tmp_path / "chain-continuity.db"
    transport = FakeAssessmentTransport()
    async with assessment_client(database_path, transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id, reported_evidence_ids = await _drive_three_assessments(client)
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )
        archive_bytes = await _download_bundle(client, engagement_id)

    bundle_path = tmp_path / "shipped.zip"
    bundle_path.write_bytes(archive_bytes)
    verification = verify_disclosure_bundle(bundle_path)
    manifest = _manifest(archive_bytes)
    chain = manifest["evidence_chain"]
    stored = _recomputed_chain(database_path)

    assert verification.valid, verification.errors
    assert verification.engagement_id == engagement_id
    # A single genesis entry proves nothing about linkage; insist on real links.
    assert len(stored) >= _EXPECTED_LINKS

    # (2) one-to-one with the evidence the engagement holds, in append order, nothing else.
    assert [item["id"] for item in chain] == list(reported_evidence_ids)
    assert [item["id"] for item in chain] == [record[0] for record in stored]
    assert [item["digest"] for item in chain] == [record[2] for record in stored]
    assert [item["previous_digest"] for item in chain] == [record[1] for record in stored]
    assert chain[0]["previous_digest"] is None
    assert [item["previous_digest"] for item in chain[1:]] == [
        item["digest"] for item in chain[:-1]
    ]

    # (3) The manifest agrees with the store, not merely with itself: the report route
    # orders by captured_at and the store by chain_index, and nothing but this asserts
    # that those two orderings are the same walk over the same records.
    assert manifest["workflow_summary"]["evidence_records"] == len(stored)
    assert manifest["engagement"]["evidence_integrity"] == "valid"
    assert [item["digest"] for item in report.json()["evidence"]] == [
        record[2] for record in stored
    ]
    assert report.json()["evidence_integrity"] == {
        "status": "valid",
        "checked_records": len(stored),
        "reason": None,
    }
    # The chain covers the same records report.json ships, which is the only evidence
    # list a disclosure reader ever sees.
    shipped_report = json.loads(_read_member(archive_bytes, "report.json"))
    assert [item["id"] for item in shipped_report["evidence"]] == [
        item["id"] for item in chain
    ]


async def test_shipped_bundle_refuses_every_cut_to_the_chain(tmp_path: Path) -> None:
    database_path = tmp_path / "chain-tamper.db"
    transport = FakeAssessmentTransport()
    async with assessment_client(database_path, transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id, _reported = await _drive_three_assessments(client)
        original = await _download_bundle(client, engagement_id)

    manifest = _manifest(original)

    changed_bytes = _tampered_copy(
        tmp_path, original, "member-bytes", {"report.json": b'{"evidence": []}'}
    )

    forged_digest = json.loads(json.dumps(manifest))
    for entry in forged_digest["files"]:
        if entry["path"] == "report.md":
            entry["sha256"] = _FABRICATED_DIGEST
    forged_manifest_digest = _tampered_copy(
        tmp_path, original, "manifest-digest", {MANIFEST_NAME: _encode_manifest(forged_digest)}
    )

    repointed = json.loads(json.dumps(manifest))
    repointed["evidence_chain"][1]["previous_digest"] = _REPOINTED_DIGEST
    repointed_link = _tampered_copy(
        tmp_path, original, "repointed-link", {MANIFEST_NAME: _encode_manifest(repointed)}
    )

    dropped = json.loads(json.dumps(manifest))
    removed = dropped["evidence_chain"].pop(1)
    dropped_from_chain = _tampered_copy(
        tmp_path, original, "dropped-link", {MANIFEST_NAME: _encode_manifest(dropped)}
    )

    truncated = json.loads(json.dumps(manifest))
    orphaned = truncated["evidence_chain"].pop()
    truncated_tail = _tampered_copy(
        tmp_path, original, "truncated-tail", {MANIFEST_NAME: _encode_manifest(truncated)}
    )

    fabricated = json.loads(json.dumps(manifest))
    fabricated["evidence_chain"].append(
        {
            "id": "01999999-9999-7999-8999-999999999999",
            "digest": _FABRICATED_DIGEST,
            "previous_digest": manifest["evidence_chain"][-1]["digest"],
            "captured_at": manifest["evidence_chain"][-1]["captured_at"],
        }
    )
    fabricated_entry = _tampered_copy(
        tmp_path, original, "fabricated-entry", {MANIFEST_NAME: _encode_manifest(fabricated)}
    )

    # A member's bytes changed: caught by the manifest's own file digest.
    changed_result = verify_disclosure_bundle(changed_bytes)
    assert not changed_result.valid
    assert "digest_mismatch:report.json" in changed_result.errors

    # A manifest digest changed: the manifest no longer describes what shipped.
    forged_result = verify_disclosure_bundle(forged_manifest_digest)
    assert not forged_result.valid
    assert "digest_mismatch:report.md" in forged_result.errors

    # A chain link repointed at a digest nothing produced.
    repointed_result = verify_disclosure_bundle(repointed_link)
    assert not repointed_result.valid
    assert "evidence_chain_broken:1" in repointed_result.errors

    # An evidence record dropped out of the chain while report.json still lists it: the
    # link into the survivor no longer matches its new predecessor.
    dropped_result = verify_disclosure_bundle(dropped_from_chain)
    assert not dropped_result.valid
    assert "evidence_chain_broken:1" in dropped_result.errors
    assert removed["id"] in {
        item["id"] for item in json.loads(_read_member(original, "report.json"))["evidence"]
    }

    # The same removal at the tail leaves every surviving link pointing at its neighbour,
    # so link checking sees nothing. Only the chain's disagreement with the count and the
    # evidence list report.json ships can catch it. Before this round the verifier called
    # such a bundle valid, which let the last -- often most damaging -- evidence record be
    # dropped from a disclosure with no refusal.
    truncated_result = verify_disclosure_bundle(truncated_tail)
    assert not truncated_result.valid
    assert not any(error.startswith("evidence_chain_broken") for error in truncated_result.errors)
    assert "evidence_chain_count_mismatch" in truncated_result.errors
    assert "evidence_chain_report_mismatch" in truncated_result.errors
    assert orphaned["id"] not in {item["id"] for item in truncated["evidence_chain"]}
    assert orphaned["id"] in {
        item["id"] for item in json.loads(_read_member(original, "report.json"))["evidence"]
    }

    # An entry appended that no stored evidence record backs: its previous_digest links
    # cleanly onto the real tail, so again nothing but the cross-checks refuses it.
    fabricated_result = verify_disclosure_bundle(fabricated_entry)
    assert not fabricated_result.valid
    assert not any(error.startswith("evidence_chain_broken") for error in fabricated_result.errors)
    assert "evidence_chain_count_mismatch" in fabricated_result.errors
    assert "evidence_chain_report_mismatch" in fabricated_result.errors


def _add_finding(
    database_path: Path,
    engagement_id: str,
    **overrides: Any,
) -> str:
    with _direct_session(database_path) as session:
        finding = Finding(
            engagement_id=EngagementId(engagement_id),
            title="Authentication bypass on the orders collection",
            vulnerability_class="CWE-306",
            affected_target="https://api.example.test/v1/orders",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            status=FindingStatus.PENDING_VERIFICATION,
            **overrides,
        )
        FindingRepository(session).add(finding)
        return str(finding.id)


async def test_critical_finding_needs_a_control_only_when_it_claims_a_differential(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "critical-review.db"
    transport = FakeAssessmentTransport()
    async with assessment_client(database_path, transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id, _reported = await _drive_three_assessments(client)
    stored = _recomputed_chain(database_path)
    # A differential claim needs two chained records: the payload capture and the control.
    assert len(stored) >= _MINIMUM_CONTROL_RECORDS
    payload_evidence = EvidenceId(stored[0][0])
    control_evidence = EvidenceId(stored[1][0])

    stated_observation = _add_finding(
        database_path,
        engagement_id,
        evidence_ids=(payload_evidence,),
        verification_method=VerificationMethod.OBSERVED,
    )
    differential_without_control = _add_finding(
        database_path,
        engagement_id,
        evidence_ids=(payload_evidence,),
        verification_method=VerificationMethod.DIFFERENTIAL,
    )
    differential_with_control = _add_finding(
        database_path,
        engagement_id,
        evidence_ids=(payload_evidence,),
        control_evidence_ids=(control_evidence,),
        verification_method=VerificationMethod.DIFFERENTIAL,
    )

    async with assessment_client(database_path, transport) as client:
        base = f"/api/v1/engagements/{engagement_id}/findings"
        observed = await client.patch(
            f"{base}/{stated_observation}",
            json={"status": "verified", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
        uncontrolled = await client.patch(
            f"{base}/{differential_without_control}",
            json={"status": "verified", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
        accepted = await client.patch(
            f"{base}/{differential_with_control}",
            json={"status": "verified", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )

    # A CRITICAL finding that states OBSERVED is now verifiable on its own evidence:
    # severity says how bad it is, not what kind of observation established it.
    assert observed.status_code == 200
    assert observed.json()["status"] == "verified"
    assert uncontrolled.status_code == 409
    assert uncontrolled.json()["detail"] == (
        "differential verification requires at least one control evidence record"
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "verified"
    assert accepted.json()["severity"] == "critical"
    # The refused transitions left no trace in the shipped report.
    statuses = {
        item["id"]: item["status"]
        for item in report.json()["findings"]
        if item["id"]
        in {stated_observation, differential_without_control, differential_with_control}
    }
    assert statuses == {
        stated_observation: "verified",
        differential_without_control: "pending_verification",
        differential_with_control: "verified",
    }
    # The control record is one of the chained evidence records, not a free-floating id.
    assert str(control_evidence) in {record[0] for record in stored}
    # And a CRITICAL finding that states no method at all never reaches storage.
    with pytest.raises(DomainValidationError, match="must state a verification method"):
        _add_finding(database_path, engagement_id, evidence_ids=(payload_evidence,))


async def test_report_never_ships_a_verified_finding_the_review_rule_would_refuse(
    tmp_path: Path,
) -> None:
    """Whatever the report calls verified must be a transition ``review_finding`` allows.

    The assessment writes findings straight through ``FindingRepository.add`` while the
    review endpoint is the only caller of ``review_finding``. When the evidence rules
    lived in ``review_finding`` the two writers of the same invariant disagreed, and the
    product shipped findings labelled ``verified`` that its own review endpoint refused
    to verify.

    Resolved by narrowing the rule: the state invariants moved into
    ``Finding.__post_init__``, so every writer is bound by them, and the severity-to-
    DIFFERENTIAL coupling was dropped -- a HIGH configuration observation has no baseline
    to be held against. Only a differential *claim* now owes a control record.
    """
    database_path = tmp_path / "verified-consistency.db"
    transport = FakeAssessmentTransport()
    async with assessment_client(database_path, transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id, _reported = await _drive_three_assessments(client)
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )

    verified_ids = [
        item["id"] for item in report.json()["findings"] if item["status"] == "verified"
    ]
    assert verified_ids, "the assessment is expected to ship verified findings"

    unreviewable: list[tuple[str, str]] = []
    with _direct_session(database_path) as session:
        repository = FindingRepository(session)
        for finding_id in verified_ids:
            entry = repository.get(FindingId(finding_id))
            assert entry is not None
            try:
                review_finding(entry.entity, FindingStatus.VERIFIED)
            except Exception as error:  # noqa: BLE001 - the message is the assertion
                unreviewable.append((entry.entity.title, str(error)))
            else:
                assert not requires_control_evidence(entry.entity) or (
                    entry.entity.control_evidence_ids
                )

    assert unreviewable == []
