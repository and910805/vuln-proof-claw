"""Shared worker-to-control-plane capture wire format.

The worker emits one :class:`CaptureEnvelope` describing exactly what it observed
so the control plane can persist tamper-evident evidence from it. This module
holds no control-plane or database dependencies so the worker image stays lean.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

CAPTURE_SCHEMA: Literal["worker-capture-v1"] = "worker-capture-v1"


class CaptureEnvelope(BaseModel):
    """A single bounded capture result produced inside the disposable worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_schema: Literal["worker-capture-v1"] = CAPTURE_SCHEMA
    status: Literal["succeeded", "failed"]
    error_code: str | None = None
    status_code: int | None = None
    final_target: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    body_base64: str | None = None
    body_sha256: str | None = None
    duration_ms: int | None = None

    @model_validator(mode="after")
    def validate_status(self) -> CaptureEnvelope:
        if self.status == "succeeded":
            missing = [
                name
                for name, value in (
                    ("status_code", self.status_code),
                    ("final_target", self.final_target),
                    ("body_base64", self.body_base64),
                    ("body_sha256", self.body_sha256),
                    ("duration_ms", self.duration_ms),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"successful capture is missing fields: {', '.join(missing)}")
        elif not self.error_code:
            raise ValueError("failed capture requires an error_code")
        return self
