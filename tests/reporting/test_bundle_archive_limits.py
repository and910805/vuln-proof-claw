"""Archive-bound and unsafe-member refusals in the offline disclosure-bundle verifier.

These tests build ZIP bytes directly instead of going through ``build_disclosure_bundle``,
because the refusals under test live in header fields the builder never emits: encryption
flags, symlink mode bits, duplicate names, and declared sizes.
"""

from __future__ import annotations

import hashlib
import json
import struct
import warnings
import zipfile
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from vuln_proof_claw.reporting.bundle import (
    MANIFEST_NAME,
    MAX_ARCHIVE_BYTES,
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_BYTES,
    MAX_MEMBERS,
    MAX_TOTAL_BYTES,
    ZIP_SYMLINK_MODE,
    verify_disclosure_bundle,
)

# Every error code _validate_archive_members can raise. Tests assert against this set so
# that a perturbation is shown to trip exactly the check it targets.
MEMBER_ERROR_CODES = frozenset(
    {
        "too_many_members",
        "duplicate_member",
        "unsafe_member_path",
        "encrypted_member",
        "symlink_member",
        "member_too_large",
        "uncompressed_size_exceeded",
        "compression_ratio_exceeded",
    }
)

_SIZED_MEMBER_NAME = "report.md"
_ONE_BYTE = b"x"
_NINE_BYTES = b"# report\n"
_EXPECTED_FILES_CHECKED = 1

_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_CENTRAL_DIRECTORY_FLAG_BITS_OFFSET = 8
_CENTRAL_DIRECTORY_COMPRESS_SIZE_OFFSET = 20
_CENTRAL_DIRECTORY_FILE_SIZE_OFFSET = 24
_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x05\x06"
_END_OF_CENTRAL_DIRECTORY_START_OFFSET = 16


def _member(name: str, *, compression: int = zipfile.ZIP_STORED) -> zipfile.ZipInfo:
    """Return a plausible regular-file member, matching what the builder emits."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = compression
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _archive(members: Sequence[tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    with warnings.catch_warnings():
        # Repeating a name is the point of the duplicate_member test.
        warnings.simplefilter("ignore", UserWarning)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for info, content in members:
                archive.writestr(info, content)
    return buffer.getvalue()


def _baseline() -> bytes:
    """One safe, stored, unencrypted member: passes every archive-member check."""
    return _archive([(_member(MANIFEST_NAME), b"{}")])


def _write(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _central_directory_offsets(raw: bytes, count: int) -> list[int]:
    """Walk the central directory, returning the byte offset of each file header."""
    end = raw.rindex(_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
    start: int = struct.unpack_from("<L", raw, end + _END_OF_CENTRAL_DIRECTORY_START_OFFSET)[0]
    offsets: list[int] = []
    for _ in range(count):
        offsets.append(start)
        name_length, extra_length, comment_length = struct.unpack_from("<3H", raw, start + 28)
        start += _CENTRAL_DIRECTORY_HEADER_SIZE + name_length + extra_length + comment_length
    return offsets


def _declare_sizes(raw: bytes, sizes: Sequence[tuple[int, int]]) -> bytes:
    """Rewrite (compress_size, file_size) per member in the central directory.

    The size checks read ``ZipInfo.file_size``, which zipfile takes from the central
    directory -- bytes an attacker fully controls. Declaring the size is therefore the
    faithful way to exercise the limits, and it is also the harder case: the verifier must
    refuse on the declaration alone, before it decompresses anything.
    """
    buffer = bytearray(raw)
    offsets = _central_directory_offsets(raw, len(sizes))
    for offset, (compress_size, file_size) in zip(offsets, sizes, strict=True):
        compress_at = offset + _CENTRAL_DIRECTORY_COMPRESS_SIZE_OFFSET
        struct.pack_into("<L", buffer, compress_at, compress_size)
        struct.pack_into("<L", buffer, offset + _CENTRAL_DIRECTORY_FILE_SIZE_OFFSET, file_size)
    return bytes(buffer)


def _declare_flag_bits(raw: bytes, flag_bits: int) -> bytes:
    """Set the general-purpose flag bits of the single member in the central directory.

    zipfile cannot write an encrypted entry, and it resets flag_bits on write, so the
    encryption bit has to be stamped into the header the verifier actually inspects.
    """
    buffer = bytearray(raw)
    offset = _central_directory_offsets(raw, 1)[0]
    struct.pack_into("<H", buffer, offset + _CENTRAL_DIRECTORY_FLAG_BITS_OFFSET, flag_bits)
    return bytes(buffer)


def test_the_baseline_archive_trips_no_archive_member_check(tmp_path: Path) -> None:
    # Each test below perturbs one thing about this archive. If the baseline itself tripped
    # a member check, none of those tests would prove what caused the refusal.
    result = verify_disclosure_bundle(_write(tmp_path, "baseline.zip", _baseline()))

    assert MEMBER_ERROR_CODES.isdisjoint(result.errors)


def test_more_members_than_the_limit_is_rejected(tmp_path: Path) -> None:
    raw = _archive(
        [(_member(f"report-{index}.json"), b"{}") for index in range(MAX_MEMBERS + 1)]
    )

    result = verify_disclosure_bundle(_write(tmp_path, "many.zip", raw))

    assert not result.valid
    assert result.errors == ("too_many_members",)


def test_exactly_the_member_limit_is_accepted(tmp_path: Path) -> None:
    # The bound is inclusive; an off-by-one here would refuse honest bundles.
    raw = _archive([(_member(f"report-{index}.json"), b"{}") for index in range(MAX_MEMBERS)])

    result = verify_disclosure_bundle(_write(tmp_path, "limit.zip", raw))

    assert "too_many_members" not in result.errors


def test_a_repeated_member_name_is_rejected(tmp_path: Path) -> None:
    # Two entries under one name let a reader and the digest check disagree about which
    # bytes the manifest covers.
    raw = _archive(
        [
            (_member(MANIFEST_NAME), b"{}"),
            (_member("report.json"), b"one"),
            (_member("report.json"), b"two"),
        ]
    )

    result = verify_disclosure_bundle(_write(tmp_path, "duplicate.zip", raw))

    assert not result.valid
    assert result.errors == ("duplicate_member",)


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("", id="empty"),
        pytest.param("/etc/passwd", id="absolute"),
        pytest.param("C:/loot.txt", id="drive-letter"),
        pytest.param("evidence/", id="trailing-slash"),
        pytest.param("../outside.txt", id="parent-escape"),
        pytest.param("nested/../../outside.txt", id="nested-parent-escape"),
        pytest.param("..", id="bare-parent"),
        pytest.param(".", id="bare-current"),
    ],
)
def test_an_unsafe_member_path_is_rejected(tmp_path: Path, name: str) -> None:
    # A reviewer may extract the bundle they were handed; any name that escapes the
    # extraction directory has to be refused before that happens.
    raw = _archive([(_member(MANIFEST_NAME), b"{}"), (_member(name), b"x")])

    result = verify_disclosure_bundle(_write(tmp_path, "unsafe.zip", raw))

    assert not result.valid
    assert "unsafe_member_path" in result.errors


def test_an_encrypted_member_is_rejected(tmp_path: Path) -> None:
    # An encrypted entry cannot be hashed, so its manifest digest would go unchecked.
    raw = _declare_flag_bits(_baseline(), 0x1)

    result = verify_disclosure_bundle(_write(tmp_path, "encrypted.zip", raw))

    assert not result.valid
    assert result.errors == ("encrypted_member",)


def test_a_symlink_member_is_rejected(tmp_path: Path) -> None:
    # On extraction a symlink member can redirect a later write outside the target tree.
    info = _member("link")
    info.external_attr = (ZIP_SYMLINK_MODE | 0o777) << 16
    raw = _archive([(_member(MANIFEST_NAME), b"{}"), (info, b"/etc/passwd")])

    result = verify_disclosure_bundle(_write(tmp_path, "symlink.zip", raw))

    assert not result.valid
    assert result.errors == ("symlink_member",)


def test_a_member_declaring_more_than_the_member_limit_is_rejected(tmp_path: Path) -> None:
    oversized = MAX_MEMBER_BYTES + 1
    raw = _declare_sizes(_baseline(), [(oversized, oversized)])

    result = verify_disclosure_bundle(_write(tmp_path, "big-member.zip", raw))

    assert not result.valid
    # Equal declared sizes keep the ratio at 1 and the total under MAX_TOTAL_BYTES, so the
    # member limit is the only thing this archive violates.
    assert result.errors == ("member_too_large",)


def test_members_declaring_more_than_the_total_limit_are_rejected(tmp_path: Path) -> None:
    names = [MANIFEST_NAME, "report.json", "report.md"]
    raw = _archive([(_member(name), b"{}") for name in names])
    # Each member sits exactly on the per-member bound, so only the total is exceeded.
    assert MAX_MEMBER_BYTES * len(names) > MAX_TOTAL_BYTES
    raw = _declare_sizes(raw, [(MAX_MEMBER_BYTES, MAX_MEMBER_BYTES)] * len(names))

    result = verify_disclosure_bundle(_write(tmp_path, "big-total.zip", raw))

    assert not result.valid
    assert result.errors == ("uncompressed_size_exceeded",)


def test_a_member_over_the_compression_ratio_is_rejected(tmp_path: Path) -> None:
    # A zip bomb: small on the wire, large once a reviewer expands it.
    raw = _archive([(_member(MANIFEST_NAME, compression=zipfile.ZIP_DEFLATED), b"0" * 200_000)])
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        info = archive.infolist()[0]
    assert info.file_size / info.compress_size > MAX_COMPRESSION_RATIO

    result = verify_disclosure_bundle(_write(tmp_path, "bomb.zip", raw))

    assert not result.valid
    assert result.errors == ("compression_ratio_exceeded",)


def test_a_member_declaring_zero_compressed_bytes_is_rejected(tmp_path: Path) -> None:
    # The ratio guard must reach this without dividing by zero.
    raw = _declare_sizes(_baseline(), [(0, 1)])

    result = verify_disclosure_bundle(_write(tmp_path, "zero-compress.zip", raw))

    assert not result.valid
    assert result.errors == ("compression_ratio_exceeded",)


def test_an_empty_member_is_not_treated_as_a_compression_bomb(tmp_path: Path) -> None:
    # An empty file is 0/0; the ratio guard is skipped for it rather than refusing.
    raw = _archive([(_member(MANIFEST_NAME), b"{}"), (_member("empty.txt"), b"")])

    result = verify_disclosure_bundle(_write(tmp_path, "empty-member.zip", raw))

    assert MEMBER_ERROR_CODES.isdisjoint(result.errors)


def test_a_member_level_refusal_still_names_the_artefact_it_rejected(tmp_path: Path) -> None:
    # A reviewer has to be able to say which exact file they refused, so the archive digest
    # is reported even when verification stops at the member checks.
    info = _member("link")
    info.external_attr = (ZIP_SYMLINK_MODE | 0o777) << 16
    raw = _archive([(_member(MANIFEST_NAME), b"{}"), (info, b"/etc/passwd")])

    result = verify_disclosure_bundle(_write(tmp_path, "cited.zip", raw))

    assert result.archive_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.files_checked == 0
    assert result.engagement_id is None


def test_a_file_over_the_archive_limit_is_rejected_before_it_is_read(tmp_path: Path) -> None:
    path = _write(tmp_path, "huge.zip", b"\0" * (MAX_ARCHIVE_BYTES + 1))

    result = verify_disclosure_bundle(path)

    assert not result.valid
    assert result.errors == ("archive_too_large",)
    # The stat() guard refuses before anything is read, so there is no digest to report.
    assert result.archive_sha256 is None


def test_an_archive_that_grows_after_stat_is_rejected_with_a_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The second length check exists because the file can change between stat() and
    # read_bytes(); unlike the first, it has the bytes in hand and can name the digest.
    oversized = b"\0" * (MAX_ARCHIVE_BYTES + 1)
    path = _write(tmp_path, "grown.zip", _baseline())

    def _read_bytes(self: Path) -> bytes:
        return oversized

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)

    result = verify_disclosure_bundle(path)

    assert not result.valid
    assert result.errors == ("archive_too_large",)
    assert result.archive_sha256 == hashlib.sha256(oversized).hexdigest()


def test_a_directory_in_place_of_a_bundle_is_reported_as_unreadable(tmp_path: Path) -> None:
    directory = tmp_path / "bundle.zip"
    directory.mkdir()

    result = verify_disclosure_bundle(directory)

    assert not result.valid
    assert result.errors == ("bundle_unreadable",)
    assert result.archive_sha256 is None


def test_a_missing_bundle_is_reported_as_unreadable(tmp_path: Path) -> None:
    result = verify_disclosure_bundle(tmp_path / "absent.zip")

    assert not result.valid
    assert result.errors == ("bundle_unreadable",)
    assert result.archive_sha256 is None


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"this is not a zip archive at all", id="not-a-zip"),
        pytest.param(b"", id="empty-file"),
        pytest.param(_baseline()[:40], id="truncated-zip"),
        pytest.param(_baseline()[:-6], id="missing-end-record"),
    ],
)
def test_bytes_that_are_not_a_readable_zip_are_rejected_with_a_digest(
    tmp_path: Path, content: bytes
) -> None:
    # Malformed input must come back as a refusal, not an exception: whoever was handed the
    # bundle runs this offline and needs a verdict plus the digest of what they refused.
    path = _write(tmp_path, "broken.zip", content)

    result = verify_disclosure_bundle(path)

    assert not result.valid
    assert result.errors == ("archive_invalid",)
    assert result.archive_sha256 == hashlib.sha256(content).hexdigest()


def _sized_bundle(tmp_path: Path, name: str, content: bytes, declared_size: Any) -> Path:
    """Write a bundle whose manifest declares ``declared_size`` for its single member.

    Every other field is correct -- the digest matches ``content``, the member set matches
    the manifest, the chain is empty -- so the declared size is the only thing that can
    make this bundle fail. Members are stored uncompressed to keep the ratio at 1.
    """
    manifest = {
        "schema_version": "v1",
        "bundle_type": "proofclaw-disclosure",
        "raw_evidence_included": False,
        "engagement": {"id": "engagement-1"},
        "files": [
            {
                "path": _SIZED_MEMBER_NAME,
                "media_type": "text/markdown",
                "size": declared_size,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        ],
        "evidence_chain": [],
    }
    raw = _archive(
        [
            (_member(MANIFEST_NAME), json.dumps(manifest).encode()),
            (_member(_SIZED_MEMBER_NAME), content),
        ]
    )
    return _write(tmp_path, name, raw)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(_ONE_BYTE, id="one-byte"),
        pytest.param(_NINE_BYTES, id="nine-bytes"),
        pytest.param(b"", id="empty"),
    ],
)
def test_an_honest_integer_declared_size_verifies(tmp_path: Path, content: bytes) -> None:
    # Anchors the type guard below: refusing non-ints must not refuse real byte counts,
    # including the 0 and 1 that a bool would have compared equal to.
    bundle = _sized_bundle(tmp_path, "size-ok.zip", content, len(content))

    result = verify_disclosure_bundle(bundle)

    assert result.valid
    assert result.errors == ()
    assert result.files_checked == _EXPECTED_FILES_CHECKED


@pytest.mark.parametrize(
    ("content", "declared_size"),
    [
        # bool is a subclass of int and True == 1, so against a one-byte member a bare
        # ``entry.get("size") != len(content)`` comparison is satisfied by ``true``. Same
        # for ``false`` against an empty member. These two are the type confusion: before
        # the isinstance guard both of these bundles verified as valid.
        pytest.param(_ONE_BYTE, True, id="true-against-one-byte"),
        pytest.param(b"", False, id="false-against-empty"),
        # 9.0 == 9 likewise; this bundle also verified as valid before the guard.
        pytest.param(_NINE_BYTES, float(len(_NINE_BYTES)), id="float-equal-to-the-length"),
        # A digit string and a null never compared equal to an int, so these two were
        # already refused. They are here so the guard cannot be written in a way that
        # starts letting them through.
        pytest.param(_NINE_BYTES, str(len(_NINE_BYTES)), id="string-of-digits"),
        pytest.param(_NINE_BYTES, None, id="null"),
    ],
)
def test_a_declared_size_that_is_not_an_integer_is_rejected(
    tmp_path: Path, content: bytes, declared_size: Any
) -> None:
    # The bundle's contract is that size and sha256 both bind the stored bytes. sha256 is
    # compared as a string and still binds, so a value that dodges the size check is not
    # by itself an integrity bypass -- but a reviewer reading "valid" is told both checks
    # passed, and one of them silently did not run.
    bundle = _sized_bundle(tmp_path, "size-type.zip", content, declared_size)

    result = verify_disclosure_bundle(bundle)

    assert not result.valid
    # Exact equality: the size check is the only thing that fired, so the digest still
    # matched and no unrelated guard is propping this assertion up.
    assert result.errors == (f"size_mismatch:{_SIZED_MEMBER_NAME}",)
    assert result.files_checked == _EXPECTED_FILES_CHECKED
