"""Disposable Playwright browser sessions with host and secret isolation.

The browser's value here is not that it renders a page. It is that an application
driving itself makes the requests it actually makes, so the surface can be *observed*
rather than inferred by reading minified JavaScript. Every recovery method that works
by parsing a bundle fails the same way — it only understands the idioms it was written
against, and a target built differently returns nothing while looking like it has
nothing. A recorded request has no idiom.

What is observed is still only a candidate surface. Nothing here probes, judges, or
promotes anything: the requests go to the same endpoint classifier as every other
discovery source, and the classifier decides what may be called.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from typing import Any, Final
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
    settle_ms: int = 2_000
    """How long to let the application keep calling after the page has loaded.

    A single-page application fetches its real data after DOMContentLoaded, so
    returning the moment the document is ready observes the boot requests and misses
    the ones worth having.
    """

    ignore_https_errors: bool = False
    """Accept a certificate that does not verify.

    Published test systems routinely carry self-signed certificates, and refusing them
    means the target cannot be examined at all. Off by default, and what it costs is
    the same as everywhere else: what is observed through such a connection attests to
    what this machine received, not necessarily to what the target sent.
    """

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
class ObservedRequest:
    """One request the application made of its own accord.

    ``carried_body`` rather than the body itself: what a request *was* is enough to
    classify an endpoint, and a login's body is a credential. Recording the shape and
    not the contents keeps this safe to write into evidence.
    """

    method: str
    url: str
    resource_type: str
    carried_body: bool
    sent_at: datetime | None = None
    """When the browser issued it, taken as it was issued.

    Recorded rather than derived from the run's start and end, because the budget
    ledger charges each request to the minute it actually left and a time inferred
    from the span would be a plausible-looking invention.
    """

    @property
    def path(self) -> str:
        parsed = urlsplit(self.url)
        return f"{parsed.path}?{parsed.query}" if parsed.query else (parsed.path or "/")


#: Resource types a browser fetches to render rather than to call an API. Excluded
#: because an inventory of stylesheets and fonts is noise that buries the endpoints.
_NOT_API: Final = frozenset(
    {"stylesheet", "image", "font", "media", "manifest", "other"}
)


@dataclass(frozen=True, slots=True)
class BrowserRunResult:
    final_url: str
    title: str
    status_code: int | None
    screenshot: bytes
    blocked_requests: tuple[str, ...]
    observed_requests: tuple[ObservedRequest, ...] = ()

    @property
    def api_requests(self) -> tuple[ObservedRequest, ...]:
        """The observed requests that look like calls rather than page furniture."""
        return tuple(
            request
            for request in self.observed_requests
            if request.resource_type not in _NOT_API
        )


def inventory(requests: tuple[ObservedRequest, ...]) -> tuple[tuple[str, str], ...]:
    """Reduce observations to the (method, path) pairs the classifier takes.

    Deduplicated, order preserved: an application that polls one endpoint sixty times
    has one endpoint, and an inventory that says sixty misrepresents the surface.
    """
    seen: dict[tuple[str, str], None] = {}
    for request in requests:
        seen.setdefault((request.method.upper(), request.path), None)
    return tuple(seen)


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
        observed: list[ObservedRequest] = []
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-first-run"],
            )
            context: Any | None = None
            try:
                context = await browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=request.ignore_https_errors,
                    service_workers="block",
                )
                context.set_default_timeout(request.timeout_ms)

                def record(outgoing: Any) -> None:
                    # Recorded after the route handler has already allowed it, so an
                    # observation is never of a request that left the scope.
                    observed.append(
                        ObservedRequest(
                            method=outgoing.method,
                            url=outgoing.url,
                            resource_type=outgoing.resource_type,
                            carried_body=outgoing.post_data is not None,
                            sent_at=datetime.now(UTC),
                        )
                    )

                context.on("request", record)

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
                # A single-page application fetches its data after the document is
                # ready; returning here would record the boot requests and miss the API.
                await page.wait_for_timeout(request.settle_ms)
                return BrowserRunResult(
                    final_url=page.url,
                    title=await page.title(),
                    status_code=response.status if response is not None else None,
                    screenshot=await page.screenshot(full_page=True),
                    blocked_requests=tuple(blocked),
                    observed_requests=tuple(observed),
                )
            finally:
                if context is not None:
                    await context.close()
                await browser.close()
