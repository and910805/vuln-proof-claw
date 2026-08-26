"""Build a MITRE ATT&CK Navigator layer from Claude Code run transcripts.

One ``stream.jsonl`` per run. Each shell command is classified into a control-plane
action type and its ATT&CK techniques, then the tool result decides the outcome.
Techniques listed with ``--track`` but never attempted are emitted too, so a gap
shows up as a tracked-but-untouched cell rather than as an absent row.

Findings are not inferred from output. Pass ``--evidence`` to assert that a
technique produced a result backed by evidence, and ``--declined`` to record a
technique that was considered and deliberately not run. Both accept a run
prefix - ``--evidence site-d:T1190`` - because a technique confirmed on one
target usually was not confirmed on the others, and applying it everywhere
would credit runs that never established it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vuln_proof_claw.mitre.layer import (
    Observation,
    Outcome,
    build_layer,
    detect_outcome,
)
from vuln_proof_claw.mitre.techniques import classify_command, targets_the_engagement

_COMMAND_KEYS = ("command", "cmd", "script")
# Fallback for plain-text results only. A structured envelope is unwrapped
# instead, because matching the field name marked every successful call as
# timed out, and "-1" also matched a return code of -15.
_TIMED_OUT = re.compile(r"\brc=-1\b|\btimed out\b")
_ENVELOPE_FIELDS = ("stdout", "stderr", "partial_results", "timed_out", "return_code")
_PAYLOAD_FIELDS = ("stdout", "stderr", "partial_results")


@dataclass(frozen=True, slots=True)
class _Invocation:
    command: str
    output: str
    timed_out: bool
    non_text_output: bool
    exit_code: int | None = None


def _iter_records(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                yield record


def _blocks(record: dict[str, Any]) -> list[dict[str, Any]]:
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else record.get("content")
    if isinstance(content, list):
        return [block for block in content if isinstance(block, dict)]
    if record.get("type") in {"tool_use", "tool_result"}:
        return [record]
    return []


def _command_of(block: dict[str, Any]) -> str | None:
    payload = block.get("input")
    if not isinstance(payload, dict):
        return None
    for key in _COMMAND_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _result_content(block: dict[str, Any]) -> tuple[str, bool]:
    """Return the readable text plus whether unreadable content was present.

    A screenshot or other binary block is still a result. Reporting it as
    empty would mark the tool as never having run.
    """
    content = block.get("content")
    if isinstance(content, str):
        return content, False
    if isinstance(content, list):
        blocks = [part for part in content if isinstance(part, dict)]
        parts = [
            part["text"] for part in blocks if isinstance(part.get("text"), str)
        ]
        return "\n".join(parts), len(parts) < len(blocks)
    return "", False


def _unwrap_envelope(text: str) -> tuple[str, bool, int | None] | None:
    """Return payload, timed-out flag and exit code from a structured result.

    A tool server answers with a JSON envelope, so text heuristics applied to
    the raw string inspect the envelope instead of the command's own output.
    Returns None when the text is not such an envelope.
    """
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    result = parsed.get("result")
    if not isinstance(result, dict) or not any(key in result for key in _ENVELOPE_FIELDS):
        return None
    pieces = [
        value for key in _PAYLOAD_FIELDS if isinstance(value := result.get(key), str) and value
    ]
    timed_out = result.get("timed_out") is True
    code = result.get("return_code")
    return "\n".join(pieces), timed_out, code if isinstance(code, int) else None


def read_invocations(path: Path) -> tuple[list[_Invocation], int]:
    """Pair tool calls with their results; return invocations and unpaired count."""
    pending: dict[str, str] = {}
    results: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for record in _iter_records(path):
        for block in _blocks(record):
            kind = block.get("type")
            if kind == "tool_use":
                command = _command_of(block)
                identifier = block.get("id")
                if command and isinstance(identifier, str):
                    pending[identifier] = command
                    order.append(identifier)
            elif kind == "tool_result":
                identifier = block.get("tool_use_id")
                if isinstance(identifier, str):
                    results[identifier] = block

    invocations: list[_Invocation] = []
    unpaired = 0
    for identifier in order:
        result = results.get(identifier)
        if result is None:
            unpaired += 1
            continue
        raw, unreadable = _result_content(result)
        envelope = _unwrap_envelope(raw)
        if envelope is None:
            output = raw
            timed_out = _TIMED_OUT.search(raw.lower()) is not None
            exit_code = None
        else:
            output, timed_out, exit_code = envelope
        invocations.append(
            _Invocation(
                command=pending[identifier],
                output=output,
                timed_out=timed_out,
                non_text_output=unreadable,
                exit_code=exit_code,
            )
        )
    return invocations, unpaired


@dataclass(slots=True)
class RunTally:
    """What one transcript produced, keeping the two kinds of miss apart.

    A command that mentions no target is out of scope and needs no attention. A
    command aimed at the target that matched nothing is a gap in the signature
    table. Reporting one number for both hides the second behind the first.
    """

    observations: list[Observation]
    unmatched: list[str]
    out_of_scope: int


def observe_run(
    path: Path,
    *,
    run: str,
    evidence_techniques: frozenset[str],
    targets: Sequence[str] = (),
) -> RunTally:
    """Classify one run's transcript into observations plus the two miss counts."""
    invocations, unpaired = read_invocations(path)
    observations: list[Observation] = []
    unmatched: list[str] = []
    out_of_scope = 0
    for invocation in invocations:
        classification = classify_command(invocation.command, targets=targets)
        if classification is None:
            if targets and not targets_the_engagement(invocation.command, targets):
                out_of_scope += 1
            else:
                unmatched.append(invocation.command)
            continue
        note = classification.action_type
        if invocation.timed_out:
            note = f"{note}, hit the time limit"
        for technique in classification.techniques:
            outcome = detect_outcome(
                stdout=invocation.output,
                has_evidence=technique in evidence_techniques,
                non_text_output=invocation.non_text_output,
            )
            observations.append(
                Observation(
                    technique_id=technique,
                    outcome=outcome,
                    run=run,
                    note=note,
                )
            )
    if unpaired:
        sys.stderr.write(f"{run}: {unpaired} tool calls had no matching result\n")
    return RunTally(observations, unmatched, out_of_scope)


def _split_run(value: str) -> tuple[str | None, str]:
    """Split an optional ``run:`` prefix from a technique id.

    A technique id never contains a colon, so a colon can only be the run
    separator. Without one the entry applies to every run.
    """
    run, separator, rest = value.partition(":")
    if not separator:
        return None, value.strip()
    return run.strip() or None, rest.strip()


def _parse_scoped(values: Sequence[str]) -> dict[str | None, set[str]]:
    """Group ``[run:]technique`` entries by the run they apply to."""
    grouped: dict[str | None, set[str]] = {}
    for value in values:
        run, technique = _split_run(value)
        if technique:
            grouped.setdefault(run, set()).add(technique)
    return grouped


def _parse_declined(values: Sequence[str]) -> dict[str | None, dict[str, str]]:
    """Group ``[run:]technique=reason`` entries by the run they apply to."""
    grouped: dict[str | None, dict[str, str]] = {}
    for value in values:
        head, _, reason = value.partition("=")
        run, technique = _split_run(head)
        if technique:
            grouped.setdefault(run, {})[technique] = reason.strip()
    return grouped


def _for_run(grouped: dict[str | None, set[str]], run: str) -> frozenset[str]:
    return frozenset(grouped.get(None, set()) | grouped.get(run, set()))


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(description="Build an ATT&CK Navigator layer.")
    parser.add_argument("transcripts", nargs="+", type=Path)
    parser.add_argument("--name", default="ProofClaw run coverage")
    parser.add_argument("--description", default="")
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="[RUN:]TECHNIQUE",
        help="assert a technique produced evidence; prefix with a run to scope it",
    )
    parser.add_argument(
        "--declined",
        action="append",
        default=[],
        metavar="[RUN:]TECHNIQUE=REASON",
        help="record a technique considered and deliberately not run",
    )
    parser.add_argument("--track", action="append", default=[], metavar="TECHNIQUE")
    parser.add_argument("--target", action="append", default=[], metavar="HOST_OR_URL")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--show-unclassified", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Write a Navigator layer for the given transcripts."""
    args = build_parser().parse_args(argv)
    evidence = _parse_scoped(args.evidence)
    declined = _parse_declined(args.declined)

    observations: list[Observation] = []
    unmatched: list[str] = []
    out_of_scope = 0
    runs: list[str] = []
    for path in args.transcripts:
        if not path.is_file():
            sys.stderr.write(f"skipping missing transcript: {path}\n")
            continue
        run = path.parent.name or path.stem
        runs.append(run)
        tally = observe_run(
            path,
            run=run,
            evidence_techniques=_for_run(evidence, run),
            targets=[item.strip() for item in args.target],
        )
        observations.extend(tally.observations)
        unmatched.extend(tally.unmatched)
        out_of_scope += tally.out_of_scope
        for scope in (None, run):
            for technique, reason in declined.get(scope, {}).items():
                observations.append(
                    Observation(
                        technique_id=technique,
                        outcome=Outcome.DECLINED,
                        run=run,
                        note=reason,
                    )
                )

    if not runs:
        sys.stderr.write("no readable transcripts\n")
        return 2

    layer = build_layer(
        observations,
        name=args.name,
        description=args.description,
        runs=runs,
        tracked_techniques=[item.strip() for item in args.track],
    )
    rendered = json.dumps(layer, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(rendered + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {args.out}\n")
    else:
        sys.stdout.write(rendered + "\n")

    if out_of_scope:
        sys.stderr.write(f"{out_of_scope} commands mentioned no target, so were skipped\n")
    if unmatched:
        sys.stderr.write(
            f"{len(unmatched)} commands aimed at a target matched no signature\n"
        )
        if args.show_unclassified:
            for command in dict.fromkeys(unmatched):
                sys.stderr.write(f"  {command[:160]}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
