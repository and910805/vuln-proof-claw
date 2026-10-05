"""Refusal tests for the evidence chain, the name/digest predicates, and result assembly."""

from __future__ import annotations

import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from vuln_proof_claw.reporting.bundle import (
    MANIFEST_NAME,
    SHA256_HEX_LENGTH,
    _safe_member_name,
    _valid_sha256,
    verify_disclosure_bundle,
)

_MEMBER_NAME = "report.md"
_MEMBER_CONTENT = b"report body\n"
_MEMBER_DIGEST = hashlib.sha256(_MEMBER_CONTENT).hexdigest()
_DIGEST_A = "a" * SHA256_HEX_LENGTH
_DIGEST_B = "b" * SHA256_HEX_LENGTH
_DIGEST_C = "c" * SHA256_HEX_LENGTH
# Survives a JSON round trip as a non-string that is also not None, so a chain item can
# declare it as its previous_digest and still be distinguishable from a reset to None.
_NON_STRING_DIGEST: Any = [_DIGEST_A]


def _chain_item(digest: object, previous: object) -> dict[str, Any]:
    return {
        "id": f"evidence-{digest}",
        "digest": digest,
        "previous_digest": previous,
        "captured_at": "2026-08-26T00:00:00+00:00",
    }


def _manifest(**overrides: Any) -> dict[str, Any]:
    """A manifest that verifies clean, so each test can perturb exactly one field."""
    manifest: dict[str, Any] = {
        "schema_version": "v1",
        "bundle_type": "proofclaw-disclosure",
        "raw_evidence_included": False,
        "engagement": {"id": "engagement-1"},
        "files": [
            {
                "path": _MEMBER_NAME,
                "media_type": "text/markdown",
                "size": len(_MEMBER_CONTENT),
                "sha256": _MEMBER_DIGEST,
            }
        ],
        "evidence_chain": [],
    }
    manifest.update(overrides)
    return manifest


def _write_bundle(path: Path, manifest: object) -> Path:
    """Write a two-member bundle holding ``manifest`` verbatim.

    Members are stored uncompressed so the compression-ratio guard never fires and
    every failure the test sees comes from the field it perturbed.
    """
    body = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode()
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(MANIFEST_NAME, body)
        archive.writestr(_MEMBER_NAME, _MEMBER_CONTENT)
    path.write_bytes(output.getvalue())
    return path


def test_a_baseline_bundle_verifies_so_perturbations_are_attributable(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path / "baseline.zip", _manifest())

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.errors == ()
    assert result.engagement_id == "engagement-1"


# --- _valid_sha256 ----------------------------------------------------------------


def test_a_non_string_digest_is_not_a_valid_sha256() -> None:
    assert not _valid_sha256(None)
    assert not _valid_sha256(0)
    assert not _valid_sha256(_DIGEST_A.encode())
    assert not _valid_sha256([_DIGEST_A])


def test_a_digest_of_the_wrong_length_is_not_a_valid_sha256() -> None:
    assert not _valid_sha256("a" * (SHA256_HEX_LENGTH - 1))
    assert not _valid_sha256("a" * (SHA256_HEX_LENGTH + 1))
    assert not _valid_sha256("")


def test_a_digest_with_non_hex_characters_is_not_a_valid_sha256() -> None:
    assert not _valid_sha256("g" * SHA256_HEX_LENGTH)
    assert not _valid_sha256(_DIGEST_A[:-1] + "z")
    assert not _valid_sha256(_DIGEST_A[:-1] + " ")


def test_an_uppercase_digest_is_refused_so_digests_compare_byte_for_byte() -> None:
    # string.hexdigits accepts A-F, so only the explicit lower() check refuses this.
    assert not _valid_sha256("A" * SHA256_HEX_LENGTH)
    assert not _valid_sha256(_DIGEST_A[:-1] + "A")


def test_a_lowercase_hex_digest_of_exact_length_is_a_valid_sha256() -> None:
    assert _valid_sha256(_DIGEST_A)
    assert _valid_sha256(_MEMBER_DIGEST)
    assert _valid_sha256("0123456789abcdef" * 4)


# --- _safe_member_name ------------------------------------------------------------


def test_plain_relative_member_names_are_safe() -> None:
    assert _safe_member_name(_MEMBER_NAME)
    assert _safe_member_name(MANIFEST_NAME)
    assert _safe_member_name("evidence/report.sarif")
    assert _safe_member_name("a/b/c.txt")


def test_an_empty_member_name_is_not_safe() -> None:
    assert not _safe_member_name("")


def test_a_backslash_member_name_is_not_safe() -> None:
    # Windows extractors treat a backslash as a separator, so it is a traversal vector.
    assert not _safe_member_name("a\\b")
    assert not _safe_member_name("..\\outside.txt")


def test_an_absolute_member_name_is_not_safe() -> None:
    assert not _safe_member_name("/etc/passwd")
    assert not _safe_member_name("//host/share")


def test_a_directory_member_name_is_not_safe() -> None:
    assert not _safe_member_name("evidence/")
    assert not _safe_member_name("/")


def test_a_drive_letter_member_name_is_not_safe() -> None:
    assert not _safe_member_name("C:/x")
    assert not _safe_member_name("C:x")


def test_a_parent_traversal_member_name_is_not_safe() -> None:
    assert not _safe_member_name("..")
    assert not _safe_member_name("../outside.txt")
    assert not _safe_member_name("a/../b")
    assert not _safe_member_name("a/..")


def test_a_dot_only_member_name_is_refused_rather_than_crashing_the_verifier() -> None:
    # PurePosixPath(".").parts is empty; indexing parts[0] used to raise IndexError,
    # which escaped verify_disclosure_bundle instead of reporting unsafe_member_path.
    assert not _safe_member_name(".")
    assert not _safe_member_name("./.")


def test_a_dot_only_member_is_reported_as_unsafe_by_the_verifier(tmp_path: Path) -> None:
    bundle = tmp_path / "dot-member.zip"
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(_manifest()).encode())
        archive.writestr(".", _MEMBER_CONTENT)
    bundle.write_bytes(output.getvalue())

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "unsafe_member_path" in result.errors
    assert result.archive_sha256 is not None


# --- _verify_chain ----------------------------------------------------------------


def test_a_non_list_evidence_chain_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-not-a-list.zip",
        _manifest(evidence_chain={"0": _chain_item(_DIGEST_A, None)}),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_invalid" in result.errors
    # A reviewer has to be able to name the exact artefact they rejected.
    assert result.archive_sha256 is not None


def test_a_missing_evidence_chain_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["evidence_chain"]
    bundle = _write_bundle(tmp_path / "chain-absent.zip", manifest)

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_invalid" in result.errors


def test_a_non_dict_chain_item_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-item-scalar.zip",
        _manifest(evidence_chain=[_DIGEST_A]),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_item_invalid" in result.errors
    assert result.archive_sha256 is not None


def test_a_non_dict_chain_item_hides_every_later_chain_problem(tmp_path: Path) -> None:
    # _verify_chain returns early on a malformed element, so one scalar smuggled into
    # the chain suppresses inspection of everything behind it.
    bundle = _write_bundle(
        tmp_path / "chain-item-hides-rest.zip",
        _manifest(
            evidence_chain=[
                _chain_item(_DIGEST_A, None),
                None,
                _chain_item("NOT-A-DIGEST", _DIGEST_C),
            ]
        ),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_item_invalid" in result.errors
    assert "evidence_digest_invalid" not in result.errors
    assert not [code for code in result.errors if code.startswith("evidence_chain_broken")]


def test_a_non_hex_evidence_digest_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-digest-non-hex.zip",
        _manifest(evidence_chain=[_chain_item("z" * SHA256_HEX_LENGTH, None)]),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_digest_invalid" in result.errors
    assert result.archive_sha256 is not None


def test_an_uppercase_evidence_digest_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-digest-uppercase.zip",
        _manifest(evidence_chain=[_chain_item("A" * SHA256_HEX_LENGTH, None)]),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_digest_invalid" in result.errors


def test_a_non_string_evidence_digest_does_not_become_the_next_expected_link(
    tmp_path: Path,
) -> None:
    # _verify_chain advances its running link with
    #   previous = digest if isinstance(digest, str) else None
    # so a non-string digest must not be adoptable as the next item's expected link.
    # Item 1 carries the non-string digest and item 2 declares that very value as its
    # previous_digest, which is what makes the reset observable: with the reset item 2 is
    # compared against None and is reported broken; without it item 2 would match and no
    # break would be reported at all.
    bundle = _write_bundle(
        tmp_path / "chain-digest-non-string.zip",
        _manifest(
            evidence_chain=[
                _chain_item(_DIGEST_A, None),
                _chain_item(_NON_STRING_DIGEST, _DIGEST_A),
                _chain_item(_DIGEST_B, _NON_STRING_DIGEST),
            ]
        ),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_digest_invalid" in result.errors
    assert "evidence_chain_broken:2" in result.errors
    # Items 0 and 1 declare the correct link, so the break must be attributed to the
    # item that trusted the non-string digest, not smeared across the whole chain.
    assert "evidence_chain_broken:0" not in result.errors
    assert "evidence_chain_broken:1" not in result.errors


def test_a_first_chain_item_that_links_to_something_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-first-linked.zip",
        _manifest(evidence_chain=[_chain_item(_DIGEST_A, _DIGEST_B)]),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_broken:0" in result.errors
    assert result.archive_sha256 is not None


def test_a_middle_chain_link_pointing_at_the_wrong_digest_is_rejected(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-middle-broken.zip",
        _manifest(
            evidence_chain=[
                _chain_item(_DIGEST_A, None),
                _chain_item(_DIGEST_B, _DIGEST_C),
                _chain_item(_DIGEST_C, _DIGEST_B),
            ]
        ),
    )

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert "evidence_chain_broken:1" in result.errors
    assert "evidence_chain_broken:0" not in result.errors
    assert "evidence_chain_broken:2" not in result.errors


def test_a_valid_multi_item_chain_is_not_flagged(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "chain-valid.zip",
        _manifest(
            evidence_chain=[
                _chain_item(_DIGEST_A, None),
                _chain_item(_DIGEST_B, _DIGEST_A),
                _chain_item(_DIGEST_C, _DIGEST_B),
            ]
        ),
    )

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.errors == ()


# --- _verify_open_archive result assembly -----------------------------------------


def test_engagement_id_is_none_when_engagement_is_missing(tmp_path: Path) -> None:
    manifest = _manifest()
    del manifest["engagement"]
    bundle = _write_bundle(tmp_path / "engagement-absent.zip", manifest)

    result = verify_disclosure_bundle(bundle)

    assert result.engagement_id is None
    assert result.valid


def test_engagement_id_is_none_when_engagement_is_not_a_dict(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "engagement-scalar.zip", _manifest(engagement="engagement-1")
    )

    result = verify_disclosure_bundle(bundle)

    # A malformed engagement block is dropped, not refused: pin the clean baseline so an
    # unrelated refusal creeping in cannot let engagement_id be None for the wrong reason.
    assert result.valid
    assert result.errors == ()
    assert result.engagement_id is None


def test_engagement_id_is_none_when_the_id_is_not_a_string(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "engagement-id-not-string.zip", _manifest(engagement={"id": ["engagement-1"]})
    )

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.errors == ()
    assert result.engagement_id is None


def test_engagement_id_is_populated_for_a_well_formed_engagement(tmp_path: Path) -> None:
    bundle = _write_bundle(
        tmp_path / "engagement-well-formed.zip",
        _manifest(engagement={"id": "engagement-42", "project_id": "project-1"}),
    )

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.engagement_id == "engagement-42"


def test_repeated_error_codes_are_deduplicated_but_keep_first_seen_order(
    tmp_path: Path,
) -> None:
    # This bundle fails at five points that the verifier records in a fixed pipeline
    # order: the three manifest-contract checks in the order _load_manifest runs them,
    # then the per-file digest comparison, then the chain. Two chain items each raise
    # evidence_digest_invalid, so the reviewer must see that code exactly once and in
    # the position where it was first recorded -- last, not sorted or hashed elsewhere.
    manifest = _manifest(
        schema_version="v2",
        bundle_type="not-proofclaw",
        raw_evidence_included=True,
        evidence_chain=[
            _chain_item("A" * SHA256_HEX_LENGTH, None),
            _chain_item("B" * SHA256_HEX_LENGTH, "A" * SHA256_HEX_LENGTH),
        ],
    )
    # Right path and right size, wrong digest: only digest_mismatch fires here.
    manifest["files"][0]["sha256"] = _DIGEST_A
    bundle = _write_bundle(tmp_path / "duplicate-codes.zip", manifest)

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    assert result.errors == (
        "manifest_schema_unsupported",
        "bundle_type_invalid",
        "raw_evidence_policy_invalid",
        f"digest_mismatch:{_MEMBER_NAME}",
        "evidence_digest_invalid",
    )
