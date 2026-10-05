"""Tests for one-to-one assignment of candidates to ground truth."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import permutations

import pytest

from vuln_proof_claw.scoring.matching import UNMATCHED, match_findings, solve_assignment


def brute_force_cost(cost: Sequence[Sequence[float]]) -> float:
    """Return the optimal total cost by trying every assignment."""
    rows = len(cost)
    columns = len(cost[0])
    if rows > columns:
        transposed = [[cost[i][j] for i in range(rows)] for j in range(columns)]
        return brute_force_cost(transposed)
    best = float("inf")
    for chosen in permutations(range(columns), rows):
        total = sum(cost[row][column] for row, column in enumerate(chosen))
        best = min(best, total)
    return best


def total_of(cost: Sequence[Sequence[float]], assignment: Sequence[int]) -> float:
    return sum(
        cost[row][column] for row, column in enumerate(assignment) if column != UNMATCHED
    )


def test_empty_input_produces_no_assignment() -> None:
    assert solve_assignment([]) == ()
    assert solve_assignment([[]]) == ()
    assert match_findings([]) == ()


def test_a_ragged_matrix_is_rejected() -> None:
    with pytest.raises(ValueError, match="rectangular"):
        solve_assignment([[1.0, 2.0], [3.0]])


@pytest.mark.parametrize(
    "cost",
    [
        [[1.0]],
        [[4.0, 1.0, 3.0], [2.0, 0.0, 5.0], [3.0, 2.0, 2.0]],
        [[1.0, 2.0, 3.0], [2.0, 4.0, 6.0]],
        [[5.0, 1.0], [2.0, 9.0], [7.0, 3.0]],
        [[0.0, 0.0], [0.0, 0.0]],
        [[-3.0, -1.0], [-2.0, -4.0]],
    ],
)
def test_assignment_matches_brute_force(cost: list[list[float]]) -> None:
    assignment = solve_assignment(cost)
    assert total_of(cost, assignment) == pytest.approx(brute_force_cost(cost))


def test_more_candidates_than_truths_leaves_some_unassigned() -> None:
    assignment = solve_assignment([[1.0], [2.0], [3.0]])
    assert sum(1 for column in assignment if column != UNMATCHED) == 1


def test_each_truth_is_claimed_once() -> None:
    similarities = [[0.9, 0.1], [0.85, 0.2], [0.8, 0.95]]
    matches = match_findings(similarities, threshold=0.5)
    assert len({match.truth_index for match in matches}) == len(matches)
    assert len({match.candidate_index for match in matches}) == len(matches)


def test_the_best_of_three_restatements_wins_the_single_entry() -> None:
    similarities = [[0.6], [0.95], [0.7]]
    matches = match_findings(similarities, threshold=0.5)
    assert len(matches) == 1
    assert matches[0].candidate_index == 1
    assert matches[0].similarity == pytest.approx(0.95)


def test_a_candidate_resembling_nothing_stays_unmatched() -> None:
    similarities = [[0.9, 0.1], [0.05, 0.02]]
    matches = match_findings(similarities, threshold=0.5)
    assert [match.candidate_index for match in matches] == [0]


def test_nothing_matches_when_every_pair_is_below_the_threshold() -> None:
    assert match_findings([[0.4, 0.3], [0.2, 0.1]], threshold=0.5) == ()


def test_a_higher_threshold_discards_weak_pairs() -> None:
    similarities = [[0.6, 0.1], [0.1, 0.55]]
    assert len(match_findings(similarities, threshold=0.5)) == 2
    assert len(match_findings(similarities, threshold=0.58)) == 1


def test_assignment_maximises_total_similarity_rather_than_being_greedy() -> None:
    # Greedy picks candidate 0 for truth 0 (0.90) and then strands candidate 1,
    # which only fits truth 0. Total similarity is higher the other way round.
    similarities = [[0.90, 0.80], [0.85, 0.00]]
    matches = match_findings(similarities, threshold=0.5)
    assert len(matches) == 2
    assignment = {match.candidate_index: match.truth_index for match in matches}
    assert assignment == {0: 1, 1: 0}
