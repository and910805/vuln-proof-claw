"""Build and verify bounded, metadata-only disclosure ZIP bundles."""

from __future__ import annotations

import hashlib
import json
import string
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from vuln_proof_claw import __version__
from vuln_proof_claw.api.schemas.reports import EngagementReport

MANIFEST_NAME = "manifest.json"
MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
MAX_MEMBER_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_MEMBERS = 16
MAX_COMPRESSION_RATIO = 200
SHA256_HEX_LENGTH = 64
ZIP_SYMLINK_MODE = 0o120000


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """Stable offline verification result."""

    valid: bool
    errors: tuple[str, ...]
    engagement_id: str | None = None
    files_checked: int = 0
    archive_sha256: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "valid": self.valid,
            "errors": list(self.errors),
            "engagement_id": self.engagement_id,
            "files_checked": self.files_checked,
            "archive_sha256": self.archive_sha256,
        }


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _readme(report: EngagementReport) -> bytes:
    return (
        "ProofClaw verifiable disclosure bundle\n"
        "\n"
        f"Engagement: {report.engagement_id}\n"
        "This archive contains metadata-only reports. Raw HTTP evidence, credentials,\n"
        "cookies, browser storage, and provider secrets are intentionally excluded.\n"
        "\n"
        "Verify offline:\n"
        "  vuln-proof-claw verify-bundle PATH_TO_BUNDLE\n"
    ).encode()


def build_disclosure_bundle(
    report: EngagementReport,
    *,
    markdown: bytes,
    html: bytes,
    sarif: bytes,
) -> bytes:
    """Return a deterministic ZIP containing reports and a digest manifest."""
    files: dict[str, tuple[str, bytes]] = {
        "README.txt": ("text/plain", _readme(report)),
        "report.html": ("text/html", html),
        "report.json": ("application/json", (report.model_dump_json(indent=2) + "\n").encode()),
        "report.md": ("text/markdown", markdown),
        "report.sarif": ("application/sarif+json", sarif),
    }
    if any(len(content) > MAX_MEMBER_BYTES for _media_type, content in files.values()):
        raise ValueError("bundle member exceeds size limit")
    manifest = {
        "schema_version": "v1",
        "bundle_type": "proofclaw-disclosure",
        "generator": {"name": "vuln-proof-claw", "version": __version__},
        "generated_at": report.generated_at.isoformat(),
        "engagement": {
            "id": report.engagement_id,
            "project_id": report.project_id,
            "evidence_integrity": report.evidence_integrity.status,
        },
        "raw_evidence_included": False,
        "workflow_summary": {
            "actions": report.counts.actions,
            "action_states": dict(sorted(report.action_states.items())),
            "evidence_records": report.counts.evidence,
            "findings": report.counts.findings,
        },
        "files": [
            {
                "path": path,
                "media_type": media_type,
                "size": len(content),
                "sha256": _sha256(content),
            }
            for path, (media_type, content) in sorted(files.items())
        ],
        "evidence_chain": [
            {
                "id": item.id,
                "digest": item.digest,
                "previous_digest": item.previous_digest,
                "captured_at": item.captured_at.isoformat(),
            }
            for item in report.evidence
        ],
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(_zip_info(MANIFEST_NAME), manifest_bytes)
        for path, (_media_type, content) in sorted(files.items()):
            archive.writestr(_zip_info(path), content)
    content = output.getvalue()
    if len(content) > MAX_ARCHIVE_BYTES:
        raise ValueError("bundle exceeds archive size limit")
    return content


def _safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        # Keep: live on POSIX, where a backslash is an ordinary filename character and
        # zipfile does not touch it. On Windows this clause never fires because
        # ZipInfo.__init__ rewrites os.sep to "/", so a stored "a\b.txt" arrives as
        # "a/b.txt". Deleting it because Windows coverage shows it dead would be a real
        # regression for Linux reviewers verifying a bundle.
        and "\\" not in name
        and not path.is_absolute()
        and not name.endswith("/")
        and bool(path.parts)
        and ":" not in path.parts[0]
        # Keep the set complete. Only ".." can fire today: pathlib collapses single "."
        # components and never yields an empty one. That is an implementation detail of
        # pathlib, not a guarantee of this module, and the cost of stating all three
        # unsafe components outright is nil.
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_HEX_LENGTH
        and all(character in string.hexdigits for character in value)
        and value == value.lower()
    )


def _valid_size(value: object, length: int) -> bool:
    """Return whether a manifest-declared size is an int equal to ``length``.

    The declared size comes from attacker-controlled JSON, so the type is checked before
    the value. ``bool`` is an ``int`` subclass and ``True == 1``, and ``1.0 == 1``, so a
    bare ``!=`` comparison lets ``"size": true`` or ``"size": 1.0`` stand in for a real
    byte count.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value == length


def _manifest_file_map(manifest: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    items = manifest.get("files")
    if not isinstance(items, list):
        errors.append("manifest_files_invalid")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            errors.append("manifest_file_invalid")
            continue
        path = item["path"]
        if path in result:
            errors.append("manifest_file_duplicate")
        result[path] = item
    return result


def _verify_chain(manifest: dict[str, Any], errors: list[str]) -> None:
    chain = manifest.get("evidence_chain")
    if not isinstance(chain, list):
        errors.append("evidence_chain_invalid")
        return
    previous: str | None = None
    for index, item in enumerate(chain):
        if not isinstance(item, dict):
            errors.append("evidence_chain_item_invalid")
            return
        digest = item.get("digest")
        linked = item.get("previous_digest")
        if not _valid_sha256(digest):
            errors.append("evidence_digest_invalid")
        if linked != previous:
            errors.append(f"evidence_chain_broken:{index}")
        previous = digest if isinstance(digest, str) else None


def _validate_archive_members(members: list[zipfile.ZipInfo]) -> list[str]:
    errors: list[str] = []
    names = [item.filename for item in members]
    if len(members) > MAX_MEMBERS:
        errors.append("too_many_members")
    if len(names) != len(set(names)):
        errors.append("duplicate_member")
    if any(not _safe_member_name(name) for name in names):
        errors.append("unsafe_member_path")
    if any(item.flag_bits & 0x1 for item in members):
        errors.append("encrypted_member")
    if any((item.external_attr >> 16) & 0o170000 == ZIP_SYMLINK_MODE for item in members):
        errors.append("symlink_member")
    if any(item.file_size > MAX_MEMBER_BYTES for item in members):
        errors.append("member_too_large")
    if sum(item.file_size for item in members) > MAX_TOTAL_BYTES:
        errors.append("uncompressed_size_exceeded")
    if any(
        item.file_size > 0
        and (
            item.compress_size == 0
            or item.file_size / item.compress_size > MAX_COMPRESSION_RATIO
        )
        for item in members
    ):
        errors.append("compression_ratio_exceeded")
    return errors


def _load_manifest(archive: zipfile.ZipFile) -> tuple[dict[str, Any], list[str]]:
    if MANIFEST_NAME not in archive.namelist():
        return {}, ["manifest_missing"]
    try:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}, ["manifest_invalid"]
    if not isinstance(manifest, dict):
        return {}, ["manifest_schema_unsupported"]
    errors: list[str] = []
    if manifest.get("schema_version") != "v1":
        errors.append("manifest_schema_unsupported")
    if manifest.get("bundle_type") != "proofclaw-disclosure":
        errors.append("bundle_type_invalid")
    if manifest.get("raw_evidence_included") is not False:
        errors.append("raw_evidence_policy_invalid")
    return manifest, errors


def _verify_open_archive(
    archive: zipfile.ZipFile, archive_digest: str
) -> BundleVerification:
    members = archive.infolist()
    names = [item.filename for item in members]
    errors = _validate_archive_members(members)
    if errors:
        return BundleVerification(
            False, tuple(dict.fromkeys(errors)), archive_sha256=archive_digest
        )
    manifest, manifest_errors = _load_manifest(archive)
    errors.extend(manifest_errors)
    file_map = _manifest_file_map(manifest, errors)
    if set(names) != {MANIFEST_NAME, *file_map}:
        errors.append("archive_members_do_not_match_manifest")
    files_checked = 0
    for name, entry in file_map.items():
        # Keep the _safe_member_name re-check: _validate_archive_members already returned
        # early on any unsafe name, so it cannot fire here today. It guards the one place
        # that turns a manifest-supplied name into a read, and is deliberately not relying
        # on a caller two frames up having bailed out first.
        if name not in names or not _safe_member_name(name):
            continue
        content = archive.read(name)
        if not _valid_size(entry.get("size"), len(content)):
            errors.append(f"size_mismatch:{name}")
        if entry.get("sha256") != _sha256(content):
            errors.append(f"digest_mismatch:{name}")
        files_checked += 1
    _verify_chain(manifest, errors)
    engagement = manifest.get("engagement")
    engagement_id = engagement.get("id") if isinstance(engagement, dict) else None
    return BundleVerification(
        not errors,
        tuple(dict.fromkeys(errors)),
        engagement_id if isinstance(engagement_id, str) else None,
        files_checked,
        archive_digest,
    )


def verify_disclosure_bundle(path: Path) -> BundleVerification:
    """Verify archive bounds, safe paths, manifest contract, file hashes, and chain links."""
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            return BundleVerification(False, ("archive_too_large",))
        archive_bytes = path.read_bytes()
    except OSError:
        return BundleVerification(False, ("bundle_unreadable",))
    archive_digest = _sha256(archive_bytes)
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        return BundleVerification(False, ("archive_too_large",), archive_sha256=archive_digest)
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
            return _verify_open_archive(archive, archive_digest)
    except zipfile.BadZipFile:
        return BundleVerification(False, ("archive_invalid",), archive_sha256=archive_digest)
