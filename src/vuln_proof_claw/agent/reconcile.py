"""Reconcile paths read from source against paths seen on the wire.

A client is often written against paths that are relative to a base it prepends at run
time. Reading its source then recovers ``/web/x`` for an endpoint it actually calls at
``/api/web/x`` — every path wrong in the same way, which is the worst shape for a
mistake to take: probing them produces a tidy page of "no handler reached" and a clean
report about a surface that was never touched.

Observation settles it, but only where the two overlap. This decides whether a prefix
is *established* rather than merely plausible: it must be corroborated by several
observations and contradicted by none. Below that bar nothing is rewritten, because a
prefix applied on thin evidence turns one set of wrong paths into another and makes
them look confirmed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

#: How many observed paths must agree before a prefix is treated as established.
#: Two can coincide; this is deliberately a judgement about evidence, not a constant
#: chosen to make a particular target work.
MINIMUM_CORROBORATIONS = 3


@dataclass(frozen=True, slots=True)
class PrefixFinding:
    """What the overlap between inference and observation supports."""

    prefix: str
    corroborations: int
    contradictions: int

    @property
    def established(self) -> bool:
        return (
            bool(self.prefix)
            and self.corroborations >= MINIMUM_CORROBORATIONS
            and self.contradictions == 0
        )

    def describe(self) -> str:
        if not self.prefix:
            return "no prefix is suggested by the observations"
        verdict = "established" if self.established else "not established"
        return (
            f"prefix {self.prefix!r} {verdict}: {self.corroborations} observation(s) "
            f"agree, {self.contradictions} contradict"
        )


def _without_query(path: str) -> str:
    return path.split("?", 1)[0]


def find_prefix(
    inferred: tuple[str, ...], observed: tuple[str, ...]
) -> PrefixFinding:
    """Return the prefix observation supports for paths read from source.

    A corroboration is an inferred path that appears in the observations only once the
    prefix is added. A contradiction is one that appears without it — proof the client
    calls that path directly, and so that no single prefix explains the set.
    """
    inferred_set = {_without_query(path) for path in inferred}
    observed_set = {_without_query(path) for path in observed}
    if not inferred_set or not observed_set:
        return PrefixFinding(prefix="", corroborations=0, contradictions=0)

    candidates: Counter[str] = Counter()
    for seen in observed_set:
        for guess in inferred_set:
            if seen.endswith(guess) and seen != guess:
                candidates[seen[: -len(guess)]] += 1

    if not candidates:
        return PrefixFinding(prefix="", corroborations=0, contradictions=0)

    prefix, corroborations = candidates.most_common(1)[0]
    contradictions = len(inferred_set & observed_set)
    return PrefixFinding(
        prefix=prefix, corroborations=corroborations, contradictions=contradictions
    )


def apply_prefix(paths: tuple[tuple[str, str], ...], prefix: str) -> tuple[tuple[str, str], ...]:
    """Prepend an established prefix to every inferred (method, path) pair."""
    if not prefix:
        return paths
    return tuple((method, f"{prefix}{path}") for method, path in paths)


__all__ = ["MINIMUM_CORROBORATIONS", "PrefixFinding", "apply_prefix", "find_prefix"]
