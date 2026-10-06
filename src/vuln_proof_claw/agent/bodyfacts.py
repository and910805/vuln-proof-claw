"""Derive one fact from a response body, so no oracle has to read one.

The judgement rules work from :class:`~vuln_proof_claw.agent.differential.ProbeResult`,
which records a digest and a length rather than content -- deliberately, so that no
verdict can rest on anyone's interpretation of what came back.

That holds as long as the facts the rules need are in the status line. One of them is
not. "An API that authenticates rejects before dispatching: 401 or 403" describes many
APIs; it does not describe the zero-trust platform whose ``/api/me`` answers an
anonymous caller with ``200`` and a JSON body stating the request was refused, every
identity field null. The status line says success and the application says no.

So the fact is extracted here, once, where the response is read: a single boolean. Not
the message, not the fields, not a classification of the content -- only whether the
body states its own failure. Everything else about the body is still reduced to a
digest before anything can see it.
"""

from __future__ import annotations

import json
from typing import Any, Final

#: Top-level fields an application uses to report the outcome of a request.
_OUTCOME_FIELDS: Final = ("success", "ok", "result", "status", "state")

#: Values of those fields that mean the request did not succeed. Compared lowercased
#: and whole: "error" is a refusal, and a message that merely contains the word is not.
_FAILURE_WORDS: Final = frozenset(
    {"error", "fail", "failed", "failure", "denied", "unauthorized", "unauthorised", "ng"}
)

#: A body larger than this is not a status envelope, and scanning it for one would be
#: reading content rather than noting a fact about the response.
_MAXIMUM_ENVELOPE_BYTES: Final = 4096


def declares_failure(  # noqa: PLR0911 - one guard per thing this must not decide
    body: bytes | str | None, *, content_type: str = ""
) -> bool:
    """Return whether a JSON body states that the request was refused.

    False for anything that is not a small JSON object, including a body that cannot be
    parsed: the absence of a declared failure is not a declared success, and guessing
    would turn this from a fact into an interpretation.
    """
    if body is None:
        return False
    if content_type and "json" not in content_type.split(";", 1)[0].strip().lower():
        return False
    raw = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    if not raw or len(raw) > _MAXIMUM_ENVELOPE_BYTES:
        return False
    try:
        parsed: Any = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(parsed, dict):
        return False

    for field in _OUTCOME_FIELDS:
        if field not in parsed:
            continue
        value = parsed[field]
        if value is False:
            return True
        if isinstance(value, str) and value.strip().lower() in _FAILURE_WORDS:
            return True
    return False


__all__ = ["declares_failure"]
