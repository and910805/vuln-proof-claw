"""Manifest contract and per-file digest refusals of the offline bundle verifier.

These tests build ZIP bytes directly instead of going through
``build_disclosure_bundle`` so that a single manifest field, member set, or
declared digest can be perturbed in isolation. Each test asserts the specific
error code, because ``not valid`` alone would also pass if an unrelated check
started firing.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from vuln_proof_claw.reporting.bundle import MANIFEST_NAME, verify_disclosure_bundle

MEMBER_NAME = "report.md"
MEMBER_CONTENT = b"# report\n"
EXPECTED_FILES_CHECKED = 1


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_entry(path: str, content: bytes) -> dict[str, Any]:
    return {
        "path": path,
        "media_type": "text/markdown",
        "size": len(content),
        "sha256": _digest(content),
    }


def _manifest() -> dict[str, Any]:
    """Return a manifest that the verifier accepts, for tests to perturb."""
    return {
        "schema_version": "v1",
        "bundle_type": "proofclaw-disclosure",
        "raw_evidence_included": False,
        "engagement": {"id": "engagement-1", "project_id": "project-1"},
        "files": [_file_entry(MEMBER_NAME, MEMBER_CONTENT)],
        "evidence_chain": [],
    }


def _json(payload: object) -> bytes:
    return json.dumps(payload).encode()


def _write_bundle(
    path: Path,
    *,
    manifest_bytes: bytes | None = None,
    members: dict[str, bytes] | None = None,
) -> Path:
    """Write a bundle. ``manifest_bytes=None`` omits ``manifest.json`` entirely.

    Members are stored uncompressed so no test trips the compression-ratio
    guard, which returns before the manifest is ever parsed.
    """
    contents = {MEMBER_NAME: MEMBER_CONTENT} if members is None else members
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        if manifest_bytes is not None:
            archive.writestr(MANIFEST_NAME, manifest_bytes)
        for name, content in contents.items():
            archive.writestr(name, content)
    return path


def test_a_baseline_handcrafted_bundle_verifies(tmp_path: Path) -> None:
    # Anchors the helper: every perturbation below changes exactly one thing
    # away from a bundle the verifier accepts.
    bundle = _write_bundle(tmp_path / "baseline.zip", manifest_bytes=_json(_manifest()))

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.errors == ()
    assert result.files_checked == EXPECTED_FILES_CHECKED
    assert result.engagement_id == "engagement-1"
    assert result.archive_sha256 == _digest(bundle.read_bytes())


def test_a_bundle_without_a_manifest_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path / "no-manifest.zip", manifest_bytes=None)

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_missing" in result.errors


def test_a_rejected_bundle_still_reports_its_archive_digest(tmp_path: Path) -> None:
    # A reviewer must be able to name the exact artefact they rejected.
    bundle = _write_bundle(tmp_path / "no-manifest-digest.zip", manifest_bytes=None)

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert result.archive_sha256 == _digest(bundle.read_bytes())


def test_a_manifest_that_is_not_json_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path / "not-json.zip", manifest_bytes=b"{not json")

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_invalid" in result.errors


def test_a_manifest_that_is_not_utf8_is_rejected(tmp_path: Path) -> None:
    # Decoding must fail closed rather than raise out of the verifier.
    bundle = _write_bundle(tmp_path / "not-utf8.zip", manifest_bytes=b'{"a": "\xff"}')

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_invalid" in result.errors


@pytest.mark.parametrize("payload", [[], "manifest", 7, True, None])
def test_a_manifest_that_is_not_an_object_is_rejected(payload: object, tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "not-object.zip", manifest_bytes=_json(payload), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_schema_unsupported" in result.errors


@pytest.mark.parametrize("version", ["v2", "1", 1, None])
def test_an_unsupported_schema_version_is_rejected(version: object, tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["schema_version"] = version
    bundle = _write_bundle(tmp_path / "schema.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_schema_unsupported" in result.errors


def test_a_missing_schema_version_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["schema_version"]
    bundle = _write_bundle(tmp_path / "no-schema.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_schema_unsupported" in result.errors


@pytest.mark.parametrize("bundle_type", ["proofclaw-internal", "", None, 3])
def test_a_foreign_bundle_type_is_rejected(bundle_type: object, tmp_path: Path) -> None:
    # A verifier handed some other product's archive must say so, not guess.
    manifest = _manifest()
    manifest["bundle_type"] = bundle_type
    bundle = _write_bundle(tmp_path / "bundle-type.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "bundle_type_invalid" in result.errors


def test_a_missing_bundle_type_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["bundle_type"]
    bundle = _write_bundle(tmp_path / "no-bundle-type.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "bundle_type_invalid" in result.errors


@pytest.mark.parametrize("declared", [True, 0, 1, "false", "", [], {}, None])
def test_raw_evidence_included_must_be_exactly_false(declared: object, tmp_path: Path) -> None:
    # The bundle's promise is "no raw evidence inside". Anything other than a
    # literal false -- including a falsey 0 or an empty string -- is an
    # unproven promise and must be refused rather than assumed.
    manifest = _manifest()
    manifest["raw_evidence_included"] = declared
    bundle = _write_bundle(tmp_path / "raw-evidence.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "raw_evidence_policy_invalid" in result.errors


def test_a_missing_raw_evidence_policy_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["raw_evidence_included"]
    bundle = _write_bundle(tmp_path / "no-raw-evidence.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "raw_evidence_policy_invalid" in result.errors


@pytest.mark.parametrize("files", [{}, "report.md", 0, None])
def test_a_files_section_that_is_not_a_list_is_rejected(files: object, tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["files"] = files
    bundle = _write_bundle(
        tmp_path / "files-invalid.zip", manifest_bytes=_json(manifest), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_files_invalid" in result.errors
    assert result.files_checked == 0


def test_a_missing_files_section_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["files"]
    bundle = _write_bundle(
        tmp_path / "no-files.zip", manifest_bytes=_json(manifest), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_files_invalid" in result.errors


@pytest.mark.parametrize("entry", ["report.md", 5, None, []])
def test_a_file_entry_that_is_not_an_object_is_rejected(entry: object, tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["files"] = [entry]
    bundle = _write_bundle(
        tmp_path / "entry-invalid.zip", manifest_bytes=_json(manifest), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_file_invalid" in result.errors


@pytest.mark.parametrize("path", [None, 12, ["report.md"], {"name": "report.md"}])
def test_a_file_entry_with_a_non_string_path_is_rejected(path: object, tmp_path: Path) -> None:
    # A non-string path would otherwise become an unhashable or unusable key
    # in the member map.
    entry = _file_entry(MEMBER_NAME, MEMBER_CONTENT)
    entry["path"] = path
    manifest = _manifest()
    manifest["files"] = [entry]
    bundle = _write_bundle(
        tmp_path / "path-invalid.zip", manifest_bytes=_json(manifest), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_file_invalid" in result.errors


def test_a_missing_file_entry_path_is_rejected(tmp_path: Path) -> None:
    entry = _file_entry(MEMBER_NAME, MEMBER_CONTENT)
    del entry["path"]
    manifest = _manifest()
    manifest["files"] = [entry]
    bundle = _write_bundle(
        tmp_path / "path-missing.zip", manifest_bytes=_json(manifest), members={}
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_file_invalid" in result.errors


def test_two_file_entries_with_the_same_path_are_rejected(tmp_path: Path) -> None:
    # Duplicate paths let one entry's digest silently shadow the other's, so
    # the archive would be checked against only one of two conflicting claims.
    manifest = _manifest()
    manifest["files"] = [
        _file_entry(MEMBER_NAME, MEMBER_CONTENT),
        _file_entry(MEMBER_NAME, b"different bytes"),
    ]
    bundle = _write_bundle(tmp_path / "duplicate-entry.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "manifest_file_duplicate" in result.errors


def test_an_archive_member_absent_from_the_manifest_is_rejected(tmp_path: Path) -> None:
    # An undeclared member is unhashed content smuggled into a signed-looking
    # bundle, so the member set must match the manifest exactly.
    manifest = _manifest()
    bundle = _write_bundle(
        tmp_path / "extra-member.zip",
        manifest_bytes=_json(manifest),
        members={MEMBER_NAME: MEMBER_CONTENT, "extra.txt": b"undeclared"},
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "archive_members_do_not_match_manifest" in result.errors


def test_a_manifest_entry_with_no_archive_member_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["files"] = [
        _file_entry(MEMBER_NAME, MEMBER_CONTENT),
        _file_entry("report.sarif", b"{}"),
    ]
    bundle = _write_bundle(tmp_path / "missing-member.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "archive_members_do_not_match_manifest" in result.errors


def test_files_checked_counts_only_members_that_were_verified(tmp_path: Path) -> None:
    # A manifest that declares more files than the archive holds must not
    # inflate files_checked: the count is what a reviewer reads as evidence of
    # how much was actually hashed.
    manifest = _manifest()
    manifest["files"] = [
        _file_entry(MEMBER_NAME, MEMBER_CONTENT),
        _file_entry("report.sarif", b"{}"),
        _file_entry("report.html", b"<html></html>"),
    ]
    bundle = _write_bundle(tmp_path / "files-checked.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert result.files_checked == EXPECTED_FILES_CHECKED


def test_a_declared_size_that_does_not_match_the_stored_bytes_is_rejected(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    manifest["files"] = [{**_file_entry(MEMBER_NAME, MEMBER_CONTENT), "size": 999}]
    bundle = _write_bundle(tmp_path / "size.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    # The code carries the member name so a reviewer knows which file failed.
    assert f"size_mismatch:{MEMBER_NAME}" in result.errors
    assert f"digest_mismatch:{MEMBER_NAME}" not in result.errors


def test_a_missing_declared_size_is_rejected(tmp_path: Path) -> None:
    entry = _file_entry(MEMBER_NAME, MEMBER_CONTENT)
    del entry["size"]
    manifest = _manifest()
    manifest["files"] = [entry]
    bundle = _write_bundle(tmp_path / "no-size.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert f"size_mismatch:{MEMBER_NAME}" in result.errors


def test_a_declared_digest_that_does_not_match_the_stored_bytes_is_rejected(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    manifest["files"] = [{**_file_entry(MEMBER_NAME, MEMBER_CONTENT), "sha256": "0" * 64}]
    bundle = _write_bundle(tmp_path / "digest.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert f"digest_mismatch:{MEMBER_NAME}" in result.errors
    assert f"size_mismatch:{MEMBER_NAME}" not in result.errors
    assert result.files_checked == EXPECTED_FILES_CHECKED


def test_a_missing_declared_digest_is_rejected(tmp_path: Path) -> None:
    # An entry that simply omits sha256 must not be treated as "nothing to
    # check"; that would be a free pass for any content.
    entry = _file_entry(MEMBER_NAME, MEMBER_CONTENT)
    del entry["sha256"]
    manifest = _manifest()
    manifest["files"] = [entry]
    bundle = _write_bundle(tmp_path / "no-digest.zip", manifest_bytes=_json(manifest))

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert f"digest_mismatch:{MEMBER_NAME}" in result.errors


def test_the_mismatching_member_is_named_among_several_files(tmp_path: Path) -> None:
    # With multiple members the error must point at the one that failed, not
    # merely report that something failed.
    other = b"<html></html>"
    manifest = _manifest()
    manifest["files"] = [
        _file_entry(MEMBER_NAME, MEMBER_CONTENT),
        {**_file_entry("report.html", other), "sha256": "1" * 64},
    ]
    bundle = _write_bundle(
        tmp_path / "which-file.zip",
        manifest_bytes=_json(manifest),
        members={MEMBER_NAME: MEMBER_CONTENT, "report.html": other},
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "digest_mismatch:report.html" in result.errors
    assert f"digest_mismatch:{MEMBER_NAME}" not in result.errors
