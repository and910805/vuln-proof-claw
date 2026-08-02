from __future__ import annotations

import pytest
from pydantic import SecretStr

from vuln_proof_claw.automation.browser import BrowserRunRequest, LoginInstruction
from vuln_proof_claw.domain.errors import DomainValidationError


def test_browser_session_keeps_credentials_secret_and_hosts_bounded() -> None:
    login = LoginInstruction(
        login_url="https://app.example.test/login",
        username_selector="#username",
        password_selector="#password",  # noqa: S106 - CSS selector
        submit_selector="button[type=submit]",
        username=SecretStr("analyst@example.test"),
        password=SecretStr("not-serialized"),
    )
    request = BrowserRunRequest(
        target="https://app.example.test/account",
        allowed_hosts=frozenset({"APP.EXAMPLE.TEST"}),
        login=login,
    )

    assert request.allowed_hosts == frozenset({"app.example.test"})
    assert "not-serialized" not in repr(request)


def test_browser_session_rejects_cross_host_login() -> None:
    login = LoginInstruction(
        login_url="https://identity.example.test/login",
        username_selector="#u",
        password_selector="#p",  # noqa: S106 - CSS selector
        submit_selector="#go",
        username=SecretStr("u"),
        password=SecretStr("p"),
    )
    with pytest.raises(DomainValidationError, match="login host"):
        BrowserRunRequest(
            target="https://app.example.test/",
            allowed_hosts=frozenset({"app.example.test"}),
            login=login,
        )


def test_browser_session_rejects_unreviewed_port() -> None:
    with pytest.raises(DomainValidationError, match="target port"):
        BrowserRunRequest(
            target="https://app.example.test:8443/",
            allowed_hosts=frozenset({"app.example.test"}),
        )
