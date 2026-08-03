from __future__ import annotations

import hashlib
import json
import warnings
import zipfile
from io import BytesIO
from pathlib import Path

from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.reporting.bundle import verify_disclosure_bundle


async def _download_bundle(database_path: Path) -> bytes:
    async with console_client(database_path) as client:
        engagement_id = await _create_engagement(client)
        response = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.bundle.zip"
        )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-sha256"] == hashlib.sha256(response.content).hexdigest()
    return response.content


async def test_bundle_endpoint_is_metadata_only_and_offline_verifiable(tmp_path: Path) -> None:
    content = await _download_bundle(tmp_path / "bundle.db")
    bundle = tmp_path / "engagement.zip"
    bundle.write_bytes(content)

    result = verify_disclosure_bundle(bundle)
    with zipfile.ZipFile(BytesIO(content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = set(archive.namelist())

    assert result.valid
    assert result.files_checked == 5
    assert result.engagement_id is not None
    assert manifest["raw_evidence_included"] is False
    assert manifest["workflow_summary"]["actions"] == 0
    assert names == {
        "manifest.json",
        "README.txt",
        "report.html",
        "report.json",
        "report.md",
        "report.sarif",
    }


async def test_bundle_verifier_rejects_content_tampering(tmp_path: Path) -> None:
    original = await _download_bundle(tmp_path / "tamper.db")
    source = zipfile.ZipFile(BytesIO(original))
    output = BytesIO()
    with source, zipfile.ZipFile(output, "w") as changed:
        for name in source.namelist():
            content = source.read(name)
            changed.writestr(name, b"tampered" if name == "report.md" else content)
    path = tmp_path / "tampered.zip"
    path.write_bytes(output.getvalue())

    result = verify_disclosure_bundle(path)

    assert not result.valid
    assert "digest_mismatch:report.md" in result.errors
    assert "size_mismatch:report.md" in result.errors


def test_bundle_verifier_rejects_unsafe_and_duplicate_members(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("../outside.txt", "no")
    duplicate = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("manifest.json", "{}")
            archive.writestr("report.json", "one")
            archive.writestr("report.json", "two")

    unsafe_result = verify_disclosure_bundle(unsafe)
    duplicate_result = verify_disclosure_bundle(duplicate)

    assert not unsafe_result.valid
    assert "unsafe_member_path" in unsafe_result.errors
    assert not duplicate_result.valid
    assert "duplicate_member" in duplicate_result.errors


def test_bundle_verifier_rejects_excessive_compression_ratio(tmp_path: Path) -> None:
    bomb = tmp_path / "compressed.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"0" * 1_000_000)

    result = verify_disclosure_bundle(bomb)

    assert not result.valid
    assert "compression_ratio_exceeded" in result.errors


def test_bundle_verifier_rejects_broken_evidence_chain(tmp_path: Path) -> None:
    bundle = tmp_path / "broken-chain.zip"
    manifest = {
        "schema_version": "v1",
        "bundle_type": "proofclaw-disclosure",
        "raw_evidence_included": False,
        "engagement": {"id": "engagement-1"},
        "files": [],
        "evidence_chain": [
            {
                "id": "evidence-1",
                "digest": "a" * 64,
                "previous_digest": "b" * 64,
                "captured_at": "2026-08-03T00:00:00Z",
            }
        ],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_broken:0" in result.errors
