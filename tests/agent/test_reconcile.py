"""Tests for deciding whether observation establishes a prefix, or only suggests one."""

from __future__ import annotations

from vuln_proof_claw.agent.reconcile import apply_prefix, find_prefix

# Taken from a live target: the client is written against /web/... and calls /api/web/...
INFERRED = (
    "/web/cpe/dashboard",
    "/web/cpe/notifies/unit",
    "/web/software/dashboard",
    "/web/software/group.simple",
    "/web/vans/snapshots",
    "/web/clients-host-discovery/network-bans",
)
OBSERVED = (
    "/api/web/cpe/dashboard",
    "/api/web/cpe/notifies/unit",
    "/api/web/software/dashboard",
    "/api/web/software/group.simple",
    "/api/web/vans/snapshots",
    "/api/web/dashboard",
)


def test_a_prefix_several_observations_agree_on_is_established() -> None:
    finding = find_prefix(INFERRED, OBSERVED)

    assert finding.prefix == "/api"
    assert finding.corroborations == 5
    assert finding.contradictions == 0
    assert finding.established


def test_one_agreement_is_not_evidence() -> None:
    """Two paths can coincide. Rewriting a hundred on that basis turns one set of
    wrong paths into another and makes them look confirmed."""
    finding = find_prefix(INFERRED, ("/api/web/cpe/dashboard",))

    assert finding.prefix == "/api"
    assert finding.corroborations == 1
    assert not finding.established


def test_a_path_called_directly_contradicts_the_prefix() -> None:
    """Proof the client reaches that path without the prefix, so no single prefix
    explains the set."""
    finding = find_prefix(INFERRED, (*OBSERVED, "/web/cpe/dashboard"))

    assert finding.contradictions == 1
    assert not finding.established


def test_nothing_in_common_suggests_nothing() -> None:
    finding = find_prefix(INFERRED, ("/totally/unrelated", "/other"))

    assert finding.prefix == ""
    assert not finding.established
    assert finding.describe() == "no prefix is suggested by the observations"


def test_an_empty_side_suggests_nothing() -> None:
    assert not find_prefix((), OBSERVED).established
    assert not find_prefix(INFERRED, ()).established


def test_a_query_string_does_not_break_the_comparison() -> None:
    finding = find_prefix(
        ("/web/a", "/web/b", "/web/c"),
        ("/api/web/a?x=1", "/api/web/b?y=2", "/api/web/c"),
    )

    assert finding.prefix == "/api"
    assert finding.established


def test_applying_a_prefix_keeps_the_method() -> None:
    assert apply_prefix((("GET", "/web/a"), ("POST", "/web/b")), "/api") == (
        ("GET", "/api/web/a"),
        ("POST", "/api/web/b"),
    )


def test_no_prefix_changes_nothing() -> None:
    pairs = (("GET", "/web/a"),)

    assert apply_prefix(pairs, "") == pairs


def test_the_finding_explains_itself() -> None:
    """An operator reading the log should see the evidence, not just the verdict."""
    described = find_prefix(INFERRED, OBSERVED).describe()

    assert "/api" in described
    assert "5 observation(s) agree" in described
