"""Turn observed run outcomes into a MITRE ATT&CK Navigator layer.

Outcome states keep apart the three things that all look like "the tool found
nothing": the tool never ran, the tool ran and produced nothing, and the tool
reported success while producing no output at all. Collapsing them is how an
environment fault gets written up as a capability result.

The emitted document targets Navigator layer format 4.5.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from vuln_proof_claw.mitre.techniques import ATTACK_DOMAIN, TECHNIQUE_NAMES

LAYER_FORMAT: Final = "4.5"
ATTACK_VERSION: Final = "17"
NAVIGATOR_VERSION: Final = "5.1.0"
# Only markers that mean the launcher failed. "permission denied" and "no such
# file or directory" were dropped: in a web test they are far more often the
# target's own answer to a probe than a sign that the tool did not run.
_TOOL_FAILURE_MARKERS: Final = (
    "command not found",
    "no such option",
    "no input provided",
    "no files found",
    "unrecognized option",
    "invalid option",
)


class Outcome(StrEnum):
    """What actually happened when a technique was exercised."""

    NOT_ATTEMPTED = "not_attempted"
    DECLINED = "declined"
    SILENT_FAILURE = "silent_failure"
    NEGATIVE = "negative"
    POSITIVE = "positive"

    @property
    def score(self) -> int:
        """Return the Navigator score used for sorting and filtering."""
        return _SCORES[self]

    @property
    def color(self) -> str:
        """Return the Navigator cell colour for this outcome."""
        return _COLORS[self]

    @property
    def label(self) -> str:
        """Return the legend label for this outcome."""
        return _LABELS[self]


_SCORES: Final = {
    Outcome.NOT_ATTEMPTED: 0,
    Outcome.DECLINED: 1,
    Outcome.SILENT_FAILURE: 2,
    Outcome.NEGATIVE: 3,
    Outcome.POSITIVE: 4,
}
_COLORS: Final = {
    Outcome.NOT_ATTEMPTED: "#d3d1c7",
    Outcome.DECLINED: "#534ab7",
    Outcome.SILENT_FAILURE: "#ba7517",
    Outcome.NEGATIVE: "#888780",
    Outcome.POSITIVE: "#a32d2d",
}
_LABELS: Final = {
    Outcome.NOT_ATTEMPTED: "tracked but never attempted",
    Outcome.DECLINED: "considered, declined by judgement",
    Outcome.SILENT_FAILURE: "tool did not actually run",
    Outcome.NEGATIVE: "ran to completion, no result",
    Outcome.POSITIVE: "result with supporting evidence",
}

# A technique that completed once is covered even if another run mis-fired, so
# NEGATIVE outranks SILENT_FAILURE. Per-run detail is preserved in metadata.
_PRECEDENCE: Final = (
    Outcome.POSITIVE,
    Outcome.NEGATIVE,
    Outcome.SILENT_FAILURE,
    Outcome.DECLINED,
    Outcome.NOT_ATTEMPTED,
)


@dataclass(frozen=True, slots=True)
class Observation:
    """One technique outcome recorded for one run."""

    technique_id: str
    outcome: Outcome
    run: str
    note: str = ""


@dataclass(slots=True)
class _Aggregate:
    outcomes: list[Observation] = field(default_factory=list)

    @property
    def strongest(self) -> Outcome:
        seen = {observation.outcome for observation in self.outcomes}
        for candidate in _PRECEDENCE:
            if candidate in seen:
                return candidate
        return Outcome.NOT_ATTEMPTED


def detect_outcome(
    *,
    stdout: str,
    has_evidence: bool = False,
    non_text_output: bool = False,
) -> Outcome:
    """Classify one command result without guessing at ground truth.

    ``has_evidence`` is the caller's assertion that a finding was recorded and
    backed by evidence, mirroring the rule that a verified finding needs at
    least one evidence record.

    ``non_text_output`` says the result carried content that is not readable as
    text, such as a screenshot. That is a result, so it must not be reported as
    the tool having failed to run.

    A run that hit a time limit but still returned partial output is a result,
    not a failure to run: the dangerous case is the tool that buffers and so
    returns nothing at all. Pass the partial output and it is treated as a
    negative; pass the empty string and it is a silent failure.
    """
    body = stdout.strip()
    lowered = body.lower()
    if any(marker in lowered for marker in _TOOL_FAILURE_MARKERS):
        return Outcome.SILENT_FAILURE
    if not body and not non_text_output:
        return Outcome.SILENT_FAILURE
    if has_evidence:
        return Outcome.POSITIVE
    return Outcome.NEGATIVE


def build_layer(
    observations: Iterable[Observation],
    *,
    name: str,
    description: str = "",
    runs: Sequence[str] = (),
    tracked_techniques: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a Navigator layer, keeping every per-run outcome in metadata."""
    aggregates: dict[str, _Aggregate] = {}
    for observation in observations:
        aggregates.setdefault(observation.technique_id, _Aggregate()).outcomes.append(observation)
    for technique_id in tracked_techniques:
        aggregates.setdefault(technique_id, _Aggregate())

    techniques: list[dict[str, Any]] = []
    for technique_id in sorted(aggregates):
        aggregate = aggregates[technique_id]
        outcome = aggregate.strongest
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": outcome.score,
                "color": outcome.color,
                "enabled": True,
                "comment": _comment(technique_id, aggregate),
                "metadata": [
                    {"name": item.run, "value": _metadata_value(item)}
                    for item in aggregate.outcomes
                ],
                "showSubtechniques": False,
            }
        )

    return {
        "name": name,
        "description": _description(description, runs),
        "domain": ATTACK_DOMAIN,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT,
        },
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#a32d2d"], "minValue": 0, "maxValue": 4},
        "legendItems": [
            {"label": f"{outcome.score} - {outcome.label}", "color": outcome.color}
            for outcome in _PRECEDENCE[::-1]
        ],
        "sorting": 3,
        "hideDisabled": False,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#f1efe8",
        "selectSubtechniquesWithParent": False,
    }


def _comment(technique_id: str, aggregate: _Aggregate) -> str:
    label = TECHNIQUE_NAMES.get(technique_id, technique_id)
    if not aggregate.outcomes:
        return f"{label} - tracked, never attempted in any run"
    counts: dict[str, int] = {}
    for item in aggregate.outcomes:
        counts[item.outcome.value] = counts.get(item.outcome.value, 0) + 1
    summary = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    return f"{label} - {summary}"


def _metadata_value(observation: Observation) -> str:
    if observation.note:
        return f"{observation.outcome.value}: {observation.note}"
    return observation.outcome.value


def _description(description: str, runs: Sequence[str]) -> str:
    if not runs:
        return description
    joined = ", ".join(runs)
    prefix = f"{description} " if description else ""
    return f"{prefix}Runs: {joined}."
