"""Operator-authored engagement definitions.

An engagement file is the written record of what a program authorized. It is the only
place scope, program rules, and rate limits come from: nothing in the system infers an
authorization boundary, and no agent may widen one.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from vuln_proof_claw.domain.autonomous import MissionBudget, MissionCadence
from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.policy.scope import EngagementScope

MAXIMUM_DEFINITION_BYTES = 1024 * 1024


class EngagementDefinitionError(Exception):
    """Raised when an engagement definition cannot be read or is invalid."""


class FrozenDefinitionModel(BaseModel):
    """Base for definition sections; unknown keys are refused."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ScopeDefinitionFile(FrozenDefinitionModel):
    """Authorized and excluded targets, as written in the program's scope."""

    include: tuple[str, ...] = ()
    include_cidrs: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    exclude_cidrs: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = (443,)
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_paths: tuple[str, ...] = ("/",)

    @model_validator(mode="after")
    def require_an_allow_boundary(self) -> ScopeDefinitionFile:
        if not self.include and not self.include_cidrs:
            raise ValueError("scope.include must name at least one host, wildcard, or CIDR")
        return self

    def as_engagement_scope(
        self,
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> EngagementScope:
        """Build the normalized, default-deny scope the policy engine enforces."""
        hostnames = tuple(item for item in self.include if not item.startswith("*."))
        wildcards = tuple(item for item in self.include if item.startswith("*."))
        denied_hostnames = tuple(item for item in self.exclude if not item.startswith("*."))
        denied_wildcards = tuple(item for item in self.exclude if item.startswith("*."))
        return EngagementScope.create(
            allowed_hostnames=hostnames,
            allowed_cidrs=self.include_cidrs,
            allowed_ports=self.allowed_ports,
            allowed_schemes=self.allowed_schemes,
            allowed_paths=self.allowed_paths,
            denied_hostnames=denied_hostnames,
            denied_cidrs=self.exclude_cidrs,
            denied_paths=self.exclude_paths,
            allowed_wildcards=wildcards,
            denied_wildcards=denied_wildcards,
            valid_from=valid_from,
            valid_until=valid_until,
        )


class ProgramRules(FrozenDefinitionModel):
    """The program's own stated rules.

    These are recorded verbatim so that an operator reviewing a finding can see which
    rules were in force. They are never inferred by the agent.
    """

    program_name: str = Field(min_length=1, max_length=255)
    allowed_testing: tuple[str, ...] = ()
    prohibited_testing: tuple[str, ...] = ()
    reporting_rules: str = ""
    authentication_required: bool = False


class RateLimits(FrozenDefinitionModel):
    """Request ceilings the program expects to be respected."""

    requests_per_minute_per_domain: int = Field(default=10, ge=1, le=10_000)
    requests_per_hour: int = Field(default=1_000, ge=1)
    requests_per_day: int = Field(default=10_000, ge=1)
    total_requests: int = Field(default=100_000, ge=1)
    maximum_concurrent_actions: int = Field(default=2, ge=1, le=64)
    maximum_lead_attempts: int = Field(default=5, ge=1, le=100)

    def as_budget(self, *, llm_tokens_per_day: int, llm_tokens_per_lead: int) -> MissionBudget:
        return MissionBudget(
            requests_per_minute_per_domain=self.requests_per_minute_per_domain,
            requests_per_hour=self.requests_per_hour,
            requests_per_day=self.requests_per_day,
            total_requests=self.total_requests,
            llm_tokens_per_day=llm_tokens_per_day,
            llm_tokens_per_lead=llm_tokens_per_lead,
            maximum_concurrent_actions=self.maximum_concurrent_actions,
            maximum_lead_attempts=self.maximum_lead_attempts,
        )


class CadenceDefinition(FrozenDefinitionModel):
    """Scheduling intervals, in seconds."""

    cycle_interval_seconds: int = 300
    http_inventory_seconds: int = 2_700
    subdomain_refresh_seconds: int = 21_600
    deep_recon_seconds: int = 86_400
    lead_retry_cooldown_seconds: int = 3_600
    stale_lead_after_seconds: int = 604_800

    def as_cadence(self) -> MissionCadence:
        return MissionCadence(**self.model_dump())


class RiskPolicyDefinition(FrozenDefinitionModel):
    """Risk ceilings for the engagement.

    ``maximum_autonomous_risk`` is capped at L1 by the domain model: anything above it
    requires a human approval record and cannot be granted here.
    """

    maximum_risk: RiskLevel = RiskLevel.L1
    auto_execute_l1: bool = False
    maximum_autonomous_risk: RiskLevel = RiskLevel.L1
    llm_tokens_per_day: int = Field(default=1_000_000, ge=0)
    llm_tokens_per_lead: int = Field(default=50_000, ge=0)

    @model_validator(mode="after")
    def refuse_destructive_autonomy(self) -> RiskPolicyDefinition:
        if self.maximum_autonomous_risk not in {RiskLevel.L0, RiskLevel.L1}:
            raise ValueError("maximum_autonomous_risk must be L0 or L1")
        if self.maximum_risk is RiskLevel.L4:
            raise ValueError("engagement definitions must not enable L4 operations")
        return self


class EngagementDefinition(FrozenDefinitionModel):
    """A complete, operator-authored authorization record."""

    name: str = Field(min_length=1, max_length=255)
    project: str = Field(min_length=1, max_length=255)
    starts_at: datetime
    ends_at: datetime
    scope: ScopeDefinitionFile
    program: ProgramRules
    rate_limits: RateLimits = RateLimits()
    cadence: CadenceDefinition = CadenceDefinition()
    risk_policy: RiskPolicyDefinition = RiskPolicyDefinition()

    @model_validator(mode="after")
    def require_a_valid_window(self) -> EngagementDefinition:
        for label, moment in (("starts_at", self.starts_at), ("ends_at", self.ends_at)):
            if moment.tzinfo is None or moment.utcoffset() is None:
                raise ValueError(f"{label} must be timezone-aware")
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be later than starts_at")
        return self

    def as_engagement_scope(self) -> EngagementScope:
        return self.scope.as_engagement_scope(
            valid_from=self.starts_at,
            valid_until=self.ends_at,
        )

    def as_budget(self) -> MissionBudget:
        return self.rate_limits.as_budget(
            llm_tokens_per_day=self.risk_policy.llm_tokens_per_day,
            llm_tokens_per_lead=self.risk_policy.llm_tokens_per_lead,
        )

    def as_cadence(self) -> MissionCadence:
        return self.cadence.as_cadence()


def parse_engagement_definition(document: str) -> EngagementDefinition:
    """Parse an engagement definition from YAML text."""
    if len(document.encode()) > MAXIMUM_DEFINITION_BYTES:
        raise EngagementDefinitionError("engagement definition exceeds the maximum size")
    try:
        payload: Any = yaml.safe_load(document)
    except yaml.YAMLError as error:
        raise EngagementDefinitionError("engagement definition is not valid YAML") from error
    if not isinstance(payload, dict):
        raise EngagementDefinitionError("engagement definition must be a mapping")
    try:
        return EngagementDefinition.model_validate(payload)
    except ValueError as error:
        raise EngagementDefinitionError(str(error)) from error


def load_engagement_definition(path: Path) -> EngagementDefinition:
    """Read and validate an engagement definition file."""
    try:
        document = path.read_text(encoding="utf-8")
    except OSError as error:
        raise EngagementDefinitionError("engagement definition could not be read") from error
    return parse_engagement_definition(document)


__all__ = [
    "CadenceDefinition",
    "EngagementDefinition",
    "EngagementDefinitionError",
    "ProgramRules",
    "RateLimits",
    "RiskPolicyDefinition",
    "ScopeDefinitionFile",
    "load_engagement_definition",
    "parse_engagement_definition",
]
