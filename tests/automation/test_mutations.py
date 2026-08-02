from __future__ import annotations

import pytest

from vuln_proof_claw.automation.mutations import (
    MutationLocation,
    MutationPlan,
    MutationSpec,
    MutationStrategy,
)
from vuln_proof_claw.domain.errors import DomainValidationError


def test_reviewed_mutation_plan_is_stable_and_applies_query_header_and_path() -> None:
    plan = MutationPlan(
        target="https://api.example.test/v1/users/7?limit=10",
        mutations=(
            MutationSpec(MutationLocation.QUERY, "limit", MutationStrategy.BOUNDARY),
            MutationSpec(
                MutationLocation.HEADER, "Accept-Language", MutationStrategy.BENIGN_MARKER
            ),
            MutationSpec(
                MutationLocation.PATH,
                "user_id",
                MutationStrategy.TYPE_MISMATCH,
                original_value="7",
            ),
        ),
        reviewed_by="operator@example.test",
        review_reason="Validate documented parameter handling",
    )

    target, headers = plan.apply({"Accept": "application/json"})

    assert target == (
        "https://api.example.test/v1/users/proofclaw-text?limit=2147483647"
    )
    assert headers["accept-language"] == "proofclaw-validation-marker"
    assert len(plan.digest) == 64
    assert plan.digest == plan.digest


def test_unreviewed_sensitive_header_is_rejected() -> None:
    with pytest.raises(DomainValidationError, match="header mutation is not reviewed"):
        MutationSpec(MutationLocation.HEADER, "Authorization", MutationStrategy.EMPTY)
