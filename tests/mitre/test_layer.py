"""Tests for outcome detection and Navigator layer construction."""

from __future__ import annotations

import pytest

from vuln_proof_claw.mitre.layer import (
    LAYER_FORMAT,
    Observation,
    Outcome,
    build_layer,
    detect_outcome,
)


def observation(technique: str, outcome: Outcome, run: str = "run-a") -> Observation:
    return Observation(technique_id=technique, outcome=outcome, run=run)


def test_blank_output_is_a_silent_failure_not_a_negative() -> None:
    assert detect_outcome(stdout="") is Outcome.SILENT_FAILURE
    assert detect_outcome(stdout="   \n ") is Outcome.SILENT_FAILURE


@pytest.mark.parametrize(
    "output",
    [
        "sh: 1: time: command not found",
        "[FTL] No input provided: no files found",
        "Error: No such option: -l",
    ],
)
def test_tool_error_markers_are_silent_failures(output: str) -> None:
    assert detect_outcome(stdout=output) is Outcome.SILENT_FAILURE


def test_a_time_limit_that_still_returned_output_is_a_result() -> None:
    # A tool that streams keeps what it produced. The dangerous case is the
    # tool that buffers and so returns nothing when it is cut off.
    assert detect_outcome(stdout="200 GET /wp-admin/") is Outcome.NEGATIVE


def test_a_time_limit_that_returned_nothing_is_a_silent_failure() -> None:
    assert detect_outcome(stdout="") is Outcome.SILENT_FAILURE


def test_completed_run_without_evidence_is_negative() -> None:
    assert detect_outcome(stdout="No plugins Found") is Outcome.NEGATIVE


def test_evidence_promotes_the_outcome_to_positive() -> None:
    assert detect_outcome(stdout="uid=33(www-data)", has_evidence=True) is Outcome.POSITIVE


def test_positive_outranks_negative_across_runs() -> None:
    layer = build_layer(
        [
            observation("T1190", Outcome.NEGATIVE, run="run-a"),
            observation("T1190", Outcome.POSITIVE, run="run-b"),
        ],
        name="two runs",
    )
    entry = layer["techniques"][0]
    assert entry["techniqueID"] == "T1190"
    assert entry["score"] == Outcome.POSITIVE.score


def test_completed_run_outranks_a_silent_failure_but_detail_is_kept() -> None:
    layer = build_layer(
        [
            observation("T1595.003", Outcome.SILENT_FAILURE, run="run-a"),
            observation("T1595.003", Outcome.NEGATIVE, run="run-b"),
        ],
        name="two runs",
    )
    entry = layer["techniques"][0]
    assert entry["score"] == Outcome.NEGATIVE.score
    recorded = {item["name"]: item["value"] for item in entry["metadata"]}
    assert recorded["run-a"] == Outcome.SILENT_FAILURE.value
    assert recorded["run-b"] == Outcome.NEGATIVE.value


def test_tracked_but_never_attempted_technique_is_still_emitted() -> None:
    layer = build_layer(
        [observation("T1190", Outcome.POSITIVE)],
        name="gap",
        tracked_techniques=["T1505.003"],
    )
    entries = {entry["techniqueID"]: entry for entry in layer["techniques"]}
    assert entries["T1505.003"]["score"] == Outcome.NOT_ATTEMPTED.score
    assert "never attempted" in entries["T1505.003"]["comment"]


def test_declined_is_distinct_from_never_attempted() -> None:
    layer = build_layer(
        [Observation("T1499.002", Outcome.DECLINED, "run-d", "judged destructive")],
        name="refusal",
    )
    entry = layer["techniques"][0]
    assert entry["score"] == Outcome.DECLINED.score
    assert entry["metadata"][0]["value"] == "declined: judged destructive"


def test_layer_envelope_is_navigator_shaped() -> None:
    layer = build_layer(
        [observation("T1190", Outcome.POSITIVE)],
        name="envelope",
        description="six runs",
        runs=["run-a", "run-b"],
    )
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == LAYER_FORMAT
    assert layer["description"] == "six runs Runs: run-a, run-b."
    assert len(layer["legendItems"]) == len(Outcome)


def test_techniques_are_sorted_for_stable_diffs() -> None:
    layer = build_layer(
        [
            observation("T1595.003", Outcome.NEGATIVE),
            observation("T1083", Outcome.POSITIVE),
            observation("T1190", Outcome.POSITIVE),
        ],
        name="sorted",
    )
    identifiers = [entry["techniqueID"] for entry in layer["techniques"]]
    assert identifiers == sorted(identifiers)


def test_a_screenshot_result_is_not_a_silent_failure() -> None:
    # The result carried content, it just was not text. Calling that a failure
    # to run would mark a working tool as broken.
    assert detect_outcome(stdout="", non_text_output=True) is Outcome.NEGATIVE


def test_a_truly_empty_result_is_still_a_silent_failure() -> None:
    assert detect_outcome(stdout="", non_text_output=False) is Outcome.SILENT_FAILURE


def test_a_targets_own_error_message_is_not_our_tool_failing() -> None:
    # A probe for a file that is not there legitimately answers like this.
    assert detect_outcome(stdout="No such file or directory") is Outcome.NEGATIVE
    assert detect_outcome(stdout="403 permission denied") is Outcome.NEGATIVE


def test_a_launcher_failure_is_still_a_silent_failure() -> None:
    assert detect_outcome(stdout="sh: 1: time: command not found") is Outcome.SILENT_FAILURE
