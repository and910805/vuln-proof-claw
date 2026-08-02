"""Canonical protected parameters shared by control plane and Worker HTTP paths."""

from __future__ import annotations

import hashlib

from vuln_proof_claw.evidence.canonical import canonical_json


def http_parameter_digest(
    *,
    method: str,
    target: str,
    headers: tuple[tuple[str, str], ...],
) -> str:
    """Bind one canonical target to the exact passive HTTP request parameters."""
    protected = canonical_json(
        {
            "headers": [list(item) for item in headers],
            "method": method,
            "target": target,
        }
    )
    return hashlib.sha256(protected).hexdigest()
