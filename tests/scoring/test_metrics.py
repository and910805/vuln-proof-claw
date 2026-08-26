"""Tests for finding-level scoring of a run against ground truth."""

from __future__ import annotations

import pytest

from vuln_proof_claw.domain.enums import FindingSeverity
from vuln_proof_claw.scoring.metrics import SEVERITY_WEIGHTS, score_run


def test_a_negative_truth_count_is_rejected() -> None:
    with pytest.raises(ValueError, match="truth_count"):
        score_run([[1.0]], truth_count=-1)


def test_a_run_that_reported_nothing_still_records_every_miss() -> None:
    report = score_run([], truth_count=3)
    assert (report.true_positives, report.false_positives, report.false_negatives) == (0, 0, 3)
    assert report.recall == 0.0
    assert report.f1 == 0.0


def test_a_perfect_run_scores_one() -> None:
    report = score_run([[1.0, 0.0], [0.0, 1.0]], truth_count=2)
    assert report.true_positives == 2
    assert report.precision == pytest.approx(1.0)
    assert report.recall == pytest.approx(1.0)
    assert report.f1 == pytest.approx(1.0)


def test_an_invented_finding_is_a_false_positive() -> None:
    report = score_run([[0.9], [0.01]], truth_count=1)
    assert report.true_positives == 1
    assert report.false_positives == 1
    assert report.duplicates == 0
    assert report.precision == pytest.approx(0.5)


def test_saying_the_same_true_thing_twice_is_a_duplicate_not_a_false_positive() -> None:
    report = score_run([[0.95], [0.80]], truth_count=1)
    assert report.true_positives == 1
    assert report.duplicates == 1
    assert report.false_positives == 0
    # Precision must not be punished for a restatement of a real finding.
    assert report.precision == pytest.approx(1.0)


def test_misses_are_counted_against_recall() -> None:
    report = score_run([[0.9, 0.0, 0.0]], truth_count=3)
    assert report.false_negatives == 2
    assert report.recall == pytest.approx(1 / 3)


def test_f_half_weighs_precision_more_heavily_than_f1() -> None:
    # High recall, poor precision: the precision-weighted score must be lower.
    report = score_run([[0.9], [0.02], [0.02]], truth_count=1)
    assert report.precision == pytest.approx(1 / 3)
    assert report.recall == pytest.approx(1.0)
    assert report.f_half < report.f1


def test_severity_weight_counts_only_matched_findings() -> None:
    report = score_run(
        [[0.95], [0.01]],
        truth_count=1,
        candidate_severities=[FindingSeverity.CRITICAL, FindingSeverity.CRITICAL],
    )
    assert report.severity_weight == SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]


def test_informational_findings_add_no_severity_weight() -> None:
    report = score_run(
        [[0.95]],
        truth_count=1,
        candidate_severities=[FindingSeverity.INFORMATIONAL],
    )
    assert report.severity_weight == 0


def test_cwe_coverage_is_deduplicated_and_normalised() -> None:
    report = score_run(
        [[0.9, 0.0], [0.0, 0.9]],
        truth_count=2,
        candidate_cwes=["cwe-22", "CWE-22"],
    )
    assert report.cwe_covered == ("CWE-22",)


def test_cwe_coverage_ignores_unmatched_candidates() -> None:
    report = score_run(
        [[0.9], [0.01]],
        truth_count=1,
        candidate_cwes=["CWE-22", "CWE-78"],
    )
    assert report.cwe_covered == ("CWE-22",)


def test_missing_cwe_labels_are_skipped_without_error() -> None:
    report = score_run([[0.9]], truth_count=1, candidate_cwes=[None])
    assert report.cwe_covered == ()


def test_report_serialises_the_numbers_a_write_up_needs() -> None:
    payload = score_run([[0.9], [0.02]], truth_count=2).as_dict()
    assert payload["true_positives"] == 1
    assert payload["false_positives"] == 1
    assert payload["false_negatives"] == 1
    assert set(payload) >= {"precision", "recall", "f1", "f_half", "duplicates"}
