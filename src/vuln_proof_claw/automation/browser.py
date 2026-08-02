"""Disposable Playwright browser sessions with host and secret isolation."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from vuln_proof_claw.domain.errors import DomainValidationError

_MAX_SELECTOR_LENGTH = 256
_MIN_TIMEOUT_MS = 1_000
_MAX_TIMEOUT_MS = 60_000


@dataclass(frozen=True, slots=True)
class LoginInstruction:
    login_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    username: SecretStr
    password: SecretStr

    def __post_init__(self) -> None:
        parsed = urlsplit(self.login_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DomainValidationError("login_url must be an absolute HTTP URL")
        for value in (self.username_selector, self.password_selector, self.submit_selector):
            if not value.strip() or len(value) > _MAX_SELECTOR_LENGTH:
                raise DomainValidationError("login selectors must contain 1-256 characters")


@dataclass(frozen=True, slots=True)
class BrowserRunRequest:
    target: str
    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int] = frozenset({80, 443})
    login: LoginInstruction | None = None
    timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        parsed = urlsplit(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DomainValidationError("browser target must be an absolute HTTP URL")
        normalized_hosts = frozenset(host.lower().rstrip(".") for host in self.allowed_hosts)
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname.lower().rstrip(".") not in normalized_hosts:
            raise DomainValidationError("browser target host is outside the isolated session scope")
        if target_port not in self.allowed_ports:
            raise DomainValidationError("browser target port is outside the isolated session scope")
        if self.login is not None:
            login_url = urlsplit(self.login.login_url)
            login_host = login_url.hostname
            if login_host is None or login_host.lower().rstrip(".") not in normalized_hosts:
                raise DomainValidationError("login host is outside the isolated session scope")
            login_port = login_url.port or (443 if login_url.scheme == "https" else 80)
            if login_port not in self.allowed_ports:
                raise DomainValidationError("login port is outside the isolated session scope")
        if not _MIN_TIMEOUT_MS <= self.timeout_ms <= _MAX_TIMEOUT_MS:
            raise DomainValidationError("browser timeout must be between 1 and 60 seconds")
        object.__setattr__(self, "allowed_hosts", normalized_hosts)


@dataclass(frozen=True, slots=True)
class BrowserRunResult:
    final_url: str
    title: str
    status_code: int | None
    screenshot: bytes
    blocked_requests: tuple[str, ...]


class IsolatedBrowserRunner:
    """Use a fresh Chromium process/context for exactly one bounded run."""

    async def run(self, request: BrowserRunRequest) -> BrowserRunResult:
        try:
            async_playwright = import_module("playwright.async_api").async_playwright
        except ImportError as error:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Playwright is not installed; install vuln-proof-claw[browser]"
            ) from error

        blocked: list[str] = []
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-first-run"],
            )
            context: Any | None = None
            try:
                context = await browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=False,
                    service_workers="block",
                )
                context.set_default_timeout(request.timeout_ms)

                async def enforce_scope(route: Any) -> None:
                    parsed_url = urlsplit(route.request.url)
                    if parsed_url.scheme in {"about", "blob", "data"}:
                        await route.continue_()
                        return
                    host = (parsed_url.hostname or "").lower().rstrip(".")
                    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                    if (
                        parsed_url.scheme not in {"http", "https"}
                        or host not in request.allowed_hosts
                        or port not in request.allowed_ports
                    ):
                        blocked.append(route.request.url)
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()

                await context.route("**/*", enforce_scope)
                page = await context.new_page()
                if request.login is not None:
                    await page.goto(request.login.login_url, wait_until="domcontentloaded")
                    await page.locator(request.login.username_selector).fill(
                        request.login.username.get_secret_value()
                    )
                    await page.locator(request.login.password_selector).fill(
                        request.login.password.get_secret_value()
                    )
                    await page.locator(request.login.submit_selector).click()
                    await page.wait_for_load_state("domcontentloaded")
                response = await page.goto(request.target, wait_until="domcontentloaded")
                return BrowserRunResult(
                    final_url=page.url,
                    title=await page.title(),
                    status_code=response.status if response is not None else None,
                    screenshot=await page.screenshot(full_page=True),
                    blocked_requests=tuple(blocked),
                )
            finally:
                if context is not None:
                    await context.close()
                await browser.close()
