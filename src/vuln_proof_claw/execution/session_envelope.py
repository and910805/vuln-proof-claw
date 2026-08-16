"""Shared browser-session capture wire format and login instruction.

A disposable browser worker receives a :class:`LoginInstruction`, performs the
login, and returns a :class:`SessionCaptureEnvelope` describing the captured
storage state. This module holds only Pydantic models so the worker image stays
free of control-plane or database dependencies.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SESSION_SCHEMA: Literal["browser-session-v1"] = "browser-session-v1"
SESSION_REQUEST_ENV = "VULN_PROOF_CLAW_SESSION_REQUEST"


class LoginInstruction(BaseModel):
    """A form-login recipe executed inside the disposable browser worker.

    The credentials are used to establish the session and are never returned or
    persisted; only the resulting storage state leaves the worker.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=1, max_length=2048)
    username: str = Field(min_length=1, max_length=1024)
    password: str = Field(min_length=1, max_length=1024)
    username_selector: str = Field(min_length=1, max_length=512)
    password_selector: str = Field(min_length=1, max_length=512)
    submit_selector: str = Field(min_length=1, max_length=512)
    success_url_substring: str | None = Field(default=None, max_length=2048)
    timeout_seconds: int = Field(default=30, ge=1, le=180)


class SessionCaptureEnvelope(BaseModel):
    """One captured browser session (or a safe failure) from the worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_schema: Literal["browser-session-v1"] = SESSION_SCHEMA
    status: Literal["succeeded", "failed"]
    error_code: str | None = None
    final_url: str | None = None
    storage_state_json: str | None = None
    cookie_names: tuple[str, ...] = ()
    storage_keys: tuple[str, ...] = ()
    duration_ms: int | None = None

    @model_validator(mode="after")
    def validate_status(self) -> SessionCaptureEnvelope:
        if self.status == "succeeded":
            if self.final_url is None or self.storage_state_json is None:
                raise ValueError("successful capture requires final_url and storage_state_json")
        elif not self.error_code:
            raise ValueError("failed capture requires an error_code")
        return self
