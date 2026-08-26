"""Finding-level scoring for a run against a ground-truth list.

Precision and recall are both reported because they fail in opposite ways: a
tool that reports one certain finding looks perfect on precision while missing
almost everything, and a tool that reports everything looks perfect on recall
while burying the operator in noise. F0.5 is included alongside F1 for the case
where a false positive costs an analyst more than a miss.

Candidates that resembled a ground-truth entry but lost the one-to-one
assignment are counted as duplicates rather than false positives. Saying the
same true thing twice is a different failure from inventing something.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from vuln_proof_claw.domain.enums import FindingSeverity
from vuln_proof_claw.scoring.matching import Match, match_findings

# Severity bands, weighted so one critical finding is not offset by a pile of
# informational ones.
SEVERITY_WEIGHTS: Final = MappingProxyType(
    {
        FindingSeverity.INFORMATIONAL: 0,
        FindingSeverity.LOW: 3,
        FindingSeverity.MEDIUM: 15,
        FindingSeverity.HIGH: 30,
        FindingSeverity.CRITICAL: 50,
    }
)


@dataclass(frozen=True, slots=True)
class ScoreReport:
    """Finding-level result of one run against ground truth."""

    true_positives: int
    false_positives: int
    false_negatives: int
    duplicates: int
    severity_weight: int
    cwe_covered: tuple[str, ...]
    matches: tuple[Match, ...]

    @property
    def precision(self) -> float:
        reported = self.true_positives + self.false_positives
        return self.true_positives / reported if reported else 0.0

    @property
    def recall(self) -> float:
        expected = self.true_positives + self.false_negatives
        return self.true_positives / expected if expected else 0.0

    @property
    def f1(self) -> float:
        return self.f_beta(1.0)

    @property
    def f_half(self) -> float:
        return self.f_beta(0.5)

    def f_beta(self, beta: float) -> float:
        """Return the weighted harmonic mean of precision and recall."""
        precision = self.precision
        recall = self.recall
        if precision <= 0.0 or recall <= 0.0:
            return 0.0
        squared = beta * beta
        return (1 + squared) * precision * recall / (squared * precision + recall)

    def as_dict(self) -> dict[str, object]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "duplicates": self.duplicates,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "f_half": round(self.f_half, 4),
            "severity_weight": self.severity_weight,
            "cwe_covered": list(self.cwe_covered),
        }


def score_run(
    similarities: Sequence[Sequence[float]],
    *,
    truth_count: int,
    candidate_severities: Sequence[FindingSeverity] = (),
    candidate_cwes: Sequence[str | None] = (),
    threshold: float = 0.5,
) -> ScoreReport:
    """Score one run's candidates against ground truth.

    ``truth_count`` is passed separately so a run that reported nothing still
    records every ground-truth entry as a miss.
    """
    if truth_count < 0:
        raise ValueError("truth_count must not be negative")
    candidate_count = len(similarities)
    matches = match_findings(similarities, threshold=threshold)
    matched_candidates = {match.candidate_index for match in matches}

    duplicates = 0
    false_positives = 0
    for index in range(candidate_count):
        if index in matched_candidates:
            continue
        row = similarities[index] if index < len(similarities) else ()
        if any(value >= threshold for value in row):
            duplicates += 1
        else:
            false_positives += 1

    true_positives = len(matches)
    weight = sum(
        SEVERITY_WEIGHTS[candidate_severities[match.candidate_index]]
        for match in matches
        if match.candidate_index < len(candidate_severities)
    )
    covered_set: set[str] = set()
    for match in matches:
        if match.candidate_index >= len(candidate_cwes):
            continue
        cwe = candidate_cwes[match.candidate_index]
        if cwe:
            covered_set.add(cwe.upper())
    covered = sorted(covered_set)
    return ScoreReport(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=max(truth_count - true_positives, 0),
        duplicates=duplicates,
        severity_weight=weight,
        cwe_covered=tuple(covered),
        matches=matches,
    )
