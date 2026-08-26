"""One-to-one assignment of reported findings to ground truth.

Counting a run by "did it mention the planted bug" rewards noisy tools: a report
listing twenty guesses will contain the right one. Scoring per finding fixes
that, but only if each ground-truth entry can be claimed once. Otherwise three
restatements of one vulnerability count as three hits.

Similarity between a candidate and a ground-truth entry is decided elsewhere -
by a judge, or by comparing keys. This module takes that matrix and settles the
assignment, maximising total similarity while letting each side be used once.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

UNMATCHED: Final = -1
_INFINITY: Final = float("inf")


@dataclass(frozen=True, slots=True)
class Match:
    """One candidate assigned to one ground-truth entry."""

    candidate_index: int
    truth_index: int
    similarity: float


class _Solver:
    """Shortest-augmenting-path Hungarian solver for rows <= columns."""

    def __init__(self, cost: Sequence[Sequence[float]], rows: int, columns: int) -> None:
        self._cost = cost
        self._rows = rows
        self._columns = columns
        self._row_potential = [0.0] * (rows + 1)
        self._column_potential = [0.0] * (columns + 1)
        self._owner = [0] * (columns + 1)
        self._previous = [0] * (columns + 1)

    def solve(self) -> tuple[int, ...]:
        for row in range(1, self._rows + 1):
            self._augment(row)
        assignment = [UNMATCHED] * self._rows
        for column in range(1, self._columns + 1):
            owner = self._owner[column]
            if owner:
                assignment[owner - 1] = column - 1
        return tuple(assignment)

    def _augment(self, row: int) -> None:
        self._owner[0] = row
        current = 0
        slack = [_INFINITY] * (self._columns + 1)
        visited = [False] * (self._columns + 1)
        while True:
            visited[current] = True
            delta, next_column = self._scan(current, slack, visited)
            self._shift(delta, slack, visited)
            current = next_column
            if self._owner[current] == 0:
                break
        while current:
            source = self._previous[current]
            self._owner[current] = self._owner[source]
            current = source

    def _scan(
        self,
        current: int,
        slack: list[float],
        visited: list[bool],
    ) -> tuple[float, int]:
        owner = self._owner[current]
        delta = _INFINITY
        next_column = 0
        for column in range(1, self._columns + 1):
            if visited[column]:
                continue
            reduced = (
                self._cost[owner - 1][column - 1]
                - self._row_potential[owner]
                - self._column_potential[column]
            )
            if reduced < slack[column]:
                slack[column] = reduced
                self._previous[column] = current
            if slack[column] < delta:
                delta = slack[column]
                next_column = column
        return delta, next_column

    def _shift(self, delta: float, slack: list[float], visited: list[bool]) -> None:
        for column in range(self._columns + 1):
            if visited[column]:
                self._row_potential[self._owner[column]] += delta
                self._column_potential[column] -= delta
            else:
                slack[column] -= delta


def solve_assignment(cost: Sequence[Sequence[float]]) -> tuple[int, ...]:
    """Return the minimum-cost assignment of each row to a distinct column.

    Rows outnumbering columns are handled by transposing, so the result always
    has one entry per row, with -1 where a row could not be assigned.
    """
    if not cost or not cost[0]:
        return ()
    rows = len(cost)
    columns = len(cost[0])
    if any(len(row) != columns for row in cost):
        raise ValueError("cost matrix must be rectangular")
    if rows > columns:
        transposed = [[cost[i][j] for i in range(rows)] for j in range(columns)]
        column_to_row = solve_assignment(transposed)
        assignment = [UNMATCHED] * rows
        for column, row in enumerate(column_to_row):
            if row != UNMATCHED:
                assignment[row] = column
        return tuple(assignment)
    return _Solver(cost, rows, columns).solve()


def match_findings(
    similarities: Sequence[Sequence[float]],
    *,
    threshold: float = 0.5,
) -> tuple[Match, ...]:
    """Assign candidates to ground truth, keeping only pairs above the threshold.

    ``similarities[i][j]`` is how well candidate ``i`` describes ground-truth
    entry ``j``. Eligible pairs carry a negative cost so the solver prefers
    them; pairs below the threshold cost nothing and are dropped afterwards, so
    a candidate that resembles nothing stays unmatched rather than being forced
    onto a leftover entry.
    """
    if not similarities or not similarities[0]:
        return ()
    cost = [[-value if value >= threshold else 0.0 for value in row] for row in similarities]
    assignment = solve_assignment(cost)

    matches: list[Match] = []
    for candidate_index, truth_index in enumerate(assignment):
        if truth_index == UNMATCHED:
            continue
        similarity = similarities[candidate_index][truth_index]
        if similarity < threshold:
            continue
        matches.append(Match(candidate_index, truth_index, similarity))
    return tuple(matches)
