"""Reviewed automation primitives for browser and API security checks."""

from vuln_proof_claw.automation.mutations import MutationLocation, MutationPlan, MutationSpec
from vuln_proof_claw.automation.security_checks import CheckResult, SecurityCheck

__all__ = [
    "CheckResult",
    "MutationLocation",
    "MutationPlan",
    "MutationSpec",
    "SecurityCheck",
]
