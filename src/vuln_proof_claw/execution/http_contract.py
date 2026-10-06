"""Canonical protected parameters shared by control plane and Worker HTTP paths."""

from __future__ import annotations

import hashlib

from vuln_proof_claw.evidence.canonical import canonical_json


def http_parameter_digest(
    *,
    method: str,
    target: str,
    headers: tuple[tuple[str, str], ...],
    query: str = "",
) -> str:
    """Bind one canonical target to the exact passive HTTP request parameters.

    ``query`` is omitted from the protected document when empty, so a request without
    one produces exactly the digest it produced before queries were carried. That keeps
    every previously issued approval and stored action valid.

    When a query is present it is part of the binding: approving one query does not
    approve another against the same path.
    """
    protected: dict[str, object] = {
        "headers": [list(item) for item in headers],
        "method": method,
        "target": target,
    }
    if query:
        protected["query"] = query
    return hashlib.sha256(canonical_json(protected)).hexdigest()
