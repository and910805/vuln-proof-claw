"""Pin the numeric bounds of the offline disclosure-bundle verifier.

Coverage and error-code exercise say nothing about the *values* of these bounds: widening
``MAX_MEMBERS`` from 16 to 4096, or ``MAX_ARCHIVE_BYTES`` from 12 MiB to 12 GiB, leaves the
rest of the suite green while gutting the only protection a third party has when they open
a bundle they were handed. These tests record what the bounds are, tie them to facts that
can be rechecked instead of remembered, and prove each one is reachable from both sides.

The ZIP central-directory surgery used for the declared-size cases is imported from
``test_bundle_archive_limits`` rather than duplicated: an attacker controls those header
bytes, and there should be exactly one implementation of forging them in the suite.
"""

from __future__ import annotations

import hashlib
import stat
import zipfile
from io import BytesIO
from pathlib import Path

from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement
from tests.reporting.test_bundle_archive_limits import (
    MEMBER_ERROR_CODES,
    _archive,
    _baseline,
    _declare_sizes,
    _member,
    _write,
)
from vuln_proof_claw.reporting.bundle import (
    MANIFEST_NAME,
    MAX_ARCHIVE_BYTES,
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_BYTES,
    MAX_MEMBERS,
    MAX_TOTAL_BYTES,
    SHA256_HEX_LENGTH,
    ZIP_SYMLINK_MODE,
    verify_disclosure_bundle,
)

_KIB = 1024
_MIB = 1024 * 1024

# A bound that sits just above what the product emits is a bound that will start refusing
# honest bundles as soon as a report grows. The emitted bundle measured below is the
# *smallest* one the product can produce (an engagement with no actions, no findings and no
# evidence), so every real bundle is larger and needs the room this factor reserves.
_REQUIRED_HEADROOM_FACTOR = 2


async def _emitted_bundle(database_path: Path) -> bytes:
    """Return the bytes of a real bundle, fetched the way a recipient receives one."""
    async with console_client(database_path) as client:
        engagement_id = await _create_engagement(client)
        response = await client.get(f"/api/v1/engagements/{engagement_id}/report.bundle.zip")
    assert response.status_code == 200
    return response.content


async def test_the_emitted_bundle_fits_inside_every_bound_with_headroom(tmp_path: Path) -> None:
    # The most important property in this file. Each bound is an upper limit the verifier
    # enforces against bundles it did not build, so it must also admit the bundles this
    # product does build -- otherwise the verifier rejects its own output and no existing
    # test notices. Asserting a factor of headroom, not merely "fits", is what makes the
    # test fail when a limit is tightened down towards the emitted size.
    content = await _emitted_bundle(tmp_path / "bounds.db")
    bundle = _write(tmp_path, "emitted.zip", content)
    with zipfile.ZipFile(BytesIO(content)) as archive:
        members = archive.infolist()
    member_count = len(members)
    largest_member = max(item.file_size for item in members)
    total_uncompressed = sum(item.file_size for item in members)
    archive_bytes = len(content)

    result = verify_disclosure_bundle(bundle)

    assert result.valid, f"the verifier rejected the product's own bundle: {result.errors}"
    assert member_count * _REQUIRED_HEADROOM_FACTOR <= MAX_MEMBERS, (
        f"emitted {member_count} members against MAX_MEMBERS={MAX_MEMBERS}: "
        f"{MAX_MEMBERS - member_count} slots of headroom"
    )
    assert largest_member * _REQUIRED_HEADROOM_FACTOR <= MAX_MEMBER_BYTES, (
        f"largest emitted member is {largest_member} B against "
        f"MAX_MEMBER_BYTES={MAX_MEMBER_BYTES} B: {MAX_MEMBER_BYTES - largest_member} B of "
        f"headroom ({MAX_MEMBER_BYTES / largest_member:.0f}x)"
    )
    assert total_uncompressed * _REQUIRED_HEADROOM_FACTOR <= MAX_TOTAL_BYTES, (
        f"emitted {total_uncompressed} B uncompressed against "
        f"MAX_TOTAL_BYTES={MAX_TOTAL_BYTES} B: {MAX_TOTAL_BYTES - total_uncompressed} B of "
        f"headroom ({MAX_TOTAL_BYTES / total_uncompressed:.0f}x)"
    )
    assert archive_bytes * _REQUIRED_HEADROOM_FACTOR <= MAX_ARCHIVE_BYTES, (
        f"emitted archive is {archive_bytes} B against "
        f"MAX_ARCHIVE_BYTES={MAX_ARCHIVE_BYTES} B: {MAX_ARCHIVE_BYTES - archive_bytes} B of "
        f"headroom ({MAX_ARCHIVE_BYTES / archive_bytes:.0f}x)"
    )


def test_the_sha256_hex_length_matches_a_real_digest() -> None:
    # _valid_sha256 rejects any manifest digest whose length differs from this constant, so
    # the constant has to be the length hashlib actually produces rather than a number
    # somebody typed. Derived here instead of asserted as 64.
    assert len(hashlib.sha256(b"").hexdigest()) == SHA256_HEX_LENGTH


def test_the_zip_symlink_mode_matches_the_platform_symlink_bits() -> None:
    # The symlink check masks a member's external attributes with 0o170000 and compares
    # against this constant, which is the POSIX file-type value for a symbolic link. Tying
    # it to stat keeps it a checked fact rather than a remembered octal.
    assert ZIP_SYMLINK_MODE == stat.S_IFLNK
    assert ZIP_SYMLINK_MODE & stat.S_IFMT(ZIP_SYMLINK_MODE) == ZIP_SYMLINK_MODE


def test_the_per_member_bound_is_not_larger_than_the_total_bound() -> None:
    # If a single member were allowed to exceed the whole-archive uncompressed budget, then
    # member_too_large could never be the only violation: every archive tripping it would
    # also trip uncompressed_size_exceeded, and the per-member limit would be untestable in
    # isolation (see test_bundle_archive_limits, which asserts exactly that one code).
    assert MAX_MEMBER_BYTES <= MAX_TOTAL_BYTES


def test_the_archive_bound_is_smaller_than_the_uncompressed_budget() -> None:
    # The archive limit applies to compressed bytes on disk; the total limit applies to what
    # those bytes expand to. An archive limit at or above the uncompressed budget would mean
    # a bundle can never declare more expansion than it is allowed to occupy, making
    # uncompressed_size_exceeded unreachable for any archive that passed the first gate.
    assert MAX_ARCHIVE_BYTES < MAX_TOTAL_BYTES


def test_the_total_budget_is_reachable_under_the_other_bounds() -> None:
    # uncompressed_size_exceeded is only a live check if some admissible archive can declare
    # more than MAX_TOTAL_BYTES: enough members, each within the per-member bound, and
    # expansion within the compression ratio a MAX_ARCHIVE_BYTES archive is permitted.
    assert MAX_MEMBERS * MAX_MEMBER_BYTES > MAX_TOTAL_BYTES
    assert MAX_ARCHIVE_BYTES * MAX_COMPRESSION_RATIO > MAX_TOTAL_BYTES


def test_the_recorded_bound_values() -> None:
    # Widening any bound means editing this test, which means reading why it was set. The
    # reasoning, not the number, is the point of each line.
    #
    # A bundle is metadata-only: reports and a manifest, no raw HTTP evidence. The product
    # emits 6 members totalling under 8 KiB (see the headroom test above), so these values
    # leave three orders of magnitude of growth while still bounding what a recipient's
    # machine has to hold in memory -- verify_disclosure_bundle reads the whole archive with
    # read_bytes() before inspecting it.
    assert MANIFEST_NAME == "manifest.json"
    # 12 MiB on the wire: bounds the read_bytes() allocation and is checked twice, once
    # against stat() and once against the bytes actually read.
    assert MAX_ARCHIVE_BYTES == 12 * _MIB
    # 10 MiB for any one file, below the archive limit so no single member can fill it.
    assert MAX_MEMBER_BYTES == 10 * _MIB
    # 24 MiB expanded, twice the archive limit: a recipient extracting the bundle knows the
    # worst-case footprint before they start.
    assert MAX_TOTAL_BYTES == 24 * _MIB
    # 16 members against the 6 the product emits: room for new report formats without
    # letting an archive hide hundreds of entries a reviewer will not read.
    assert MAX_MEMBERS == 16
    # 200:1 expansion. Deflate on text reaches roughly 3:1 (the emitted manifest does), so
    # this is far above anything honest while still refusing a bomb, whose ratio runs into
    # the thousands.
    assert MAX_COMPRESSION_RATIO == 200
    # Derived facts, restated here so the whole set is visible in one place; the tests above
    # check them against hashlib and stat.
    assert SHA256_HEX_LENGTH == 64
    assert ZIP_SYMLINK_MODE == 0o120000


def test_a_member_declaring_exactly_the_per_member_bound_is_accepted(tmp_path: Path) -> None:
    # test_bundle_archive_limits covers MAX_MEMBER_BYTES + 1; this is the other side of that
    # bound. Equal declared sizes hold the ratio at 1, and one member of MAX_MEMBER_BYTES
    # stays under MAX_TOTAL_BYTES, so nothing else can account for a refusal.
    raw = _declare_sizes(_baseline(), [(MAX_MEMBER_BYTES, MAX_MEMBER_BYTES)])

    result = verify_disclosure_bundle(_write(tmp_path, "member-at-limit.zip", raw))

    assert MEMBER_ERROR_CODES.isdisjoint(result.errors)


def test_members_declaring_exactly_the_total_bound_are_accepted(tmp_path: Path) -> None:
    # Three members whose declared sizes sum to exactly MAX_TOTAL_BYTES, each within the
    # per-member bound. The check is ``>``, so this must pass.
    sizes = [MAX_MEMBER_BYTES, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES - 2 * MAX_MEMBER_BYTES]
    assert sum(sizes) == MAX_TOTAL_BYTES
    names = [MANIFEST_NAME, "report.json", "report.md"]
    raw = _archive([(_member(name), b"{}") for name in names])
    raw = _declare_sizes(raw, [(size, size) for size in sizes])

    result = verify_disclosure_bundle(_write(tmp_path, "total-at-limit.zip", raw))

    assert MEMBER_ERROR_CODES.isdisjoint(result.errors)


def test_members_declaring_one_byte_over_the_total_bound_are_rejected(tmp_path: Path) -> None:
    # The existing over-the-total test declares 30 MiB against a 24 MiB budget, so it cannot
    # tell where the refusal begins. This one is computed from the bound, so it does not
    # notice the bound being widened -- that is what test_the_recorded_bound_values is for --
    # but it does prove the total gate exists and starts refusing at exactly one byte over.
    sizes = [MAX_MEMBER_BYTES, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES - 2 * MAX_MEMBER_BYTES + 1]
    assert sum(sizes) == MAX_TOTAL_BYTES + 1
    names = [MANIFEST_NAME, "report.json", "report.md"]
    raw = _archive([(_member(name), b"{}") for name in names])
    raw = _declare_sizes(raw, [(size, size) for size in sizes])

    result = verify_disclosure_bundle(_write(tmp_path, "total-over-limit.zip", raw))

    assert not result.valid
    assert result.errors == ("uncompressed_size_exceeded",)


def test_a_member_declaring_exactly_the_compression_ratio_is_accepted(tmp_path: Path) -> None:
    # The guard refuses a ratio strictly greater than MAX_COMPRESSION_RATIO. A member that
    # expands by exactly that factor is admissible, and an off-by-one here would refuse
    # well-compressed honest reports.
    compressed = _KIB
    raw = _declare_sizes(_baseline(), [(compressed, compressed * MAX_COMPRESSION_RATIO)])

    result = verify_disclosure_bundle(_write(tmp_path, "ratio-at-limit.zip", raw))

    assert MEMBER_ERROR_CODES.isdisjoint(result.errors)


def test_a_member_one_notch_over_the_compression_ratio_is_rejected(tmp_path: Path) -> None:
    # The existing bomb test runs at a ratio in the hundreds; this one sits one byte above
    # the bound. Being computed from MAX_COMPRESSION_RATIO, it stays green if that number is
    # widened (test_the_recorded_bound_values catches that); what it pins is that the guard
    # is live and refuses as soon as the declared expansion passes the bound at all.
    compressed = _KIB
    raw = _declare_sizes(_baseline(), [(compressed, compressed * MAX_COMPRESSION_RATIO + 1)])

    result = verify_disclosure_bundle(_write(tmp_path, "ratio-over-limit.zip", raw))

    assert not result.valid
    assert result.errors == ("compression_ratio_exceeded",)


def test_a_file_of_exactly_the_archive_bound_is_not_refused_as_too_large(tmp_path: Path) -> None:
    # The size gates use ``>``, so a file of exactly MAX_ARCHIVE_BYTES must get past both of
    # them and be judged on its contents. These bytes are not a ZIP, hence archive_invalid:
    # the point is which refusal comes back, not that the file is accepted.
    path = _write(tmp_path, "at-limit.zip", b"\0" * MAX_ARCHIVE_BYTES)

    result = verify_disclosure_bundle(path)

    assert result.errors == ("archive_invalid",)
    assert result.archive_sha256 is not None
