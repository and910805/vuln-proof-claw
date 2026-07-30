"""Stable v1 health response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthSchema(BaseModel):
    """Strict base for public health contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    service: Literal["vuln-proof-claw"] = "vuln-proof-claw"


class LivenessResponse(HealthSchema):
    """Process liveness without downstream dependency checks."""

    status: Literal["ok"] = "ok"
    version: str


class ReadinessCheck(BaseModel):
    """One safe dependency status."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    status: Literal["ready", "not_ready"]
    code: str


class ReadinessResponse(HealthSchema):
    """Aggregated readiness result."""

    status: Literal["ready", "not_ready"]
    checks: tuple[ReadinessCheck, ...]
