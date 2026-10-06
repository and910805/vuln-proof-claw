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

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from typing import Any, Final
from urllib.parse import parse_qsl, urlsplit

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

    continue_selector: str | None = None
    """Clicked after signing in, when the application does not land you in the console.

    Some products stop at a chooser — pick an identity, then proceed. Observed without
    this step, a run records the sign-in and the handful of calls that chooser makes,
    and reports them as the application's surface.

    Naming it matters here more than anywhere else: on this engagement that screen puts
    a change-password button beside the one that proceeds, and the rules forbid changing
    a shared account's password. Anything that found its way forward by clicking what
    looked right would eventually click that.
    """

    open_selector: str | None = None
    """Clicked before the fields are filled, when the form is behind something.

    A landing page with a single button that reveals the real form is common, and
    without this the fill fails on elements that are not there yet — which reads as a
    broken selector rather than a form that had not been opened.

    One click, named explicitly. The agent never explores a page by clicking: on this
    engagement the same application carries a change-password form, and the rules
    forbid changing a shared account's password. Every element this touches is one an
    operator named.
    """

    def __post_init__(self) -> None:
        parsed = urlsplit(self.login_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DomainValidationError("login_url must be an absolute HTTP URL")
        selectors = [self.username_selector, self.password_selector, self.submit_selector]
        selectors.extend(
            value
            for value in (self.open_selector, self.continue_selector)
            if value is not None
        )
        for value in selectors:
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

    navigate_after_login: bool = False
    """Load ``target`` again once signed in.

    Off by default, because a single-page application keeps its access token in memory
    and a fresh navigation discards it: the app reloads, finds no session, and routes
    straight back to the login screen. Observed that way, a run records the handful of
    calls made between signing in and being thrown out, and reports them as the
    application's whole surface.

    Signing in already leaves the browser where the application decided to put you, so
    there is normally nowhere to navigate to.
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


def body_field_names(body: str | None) -> tuple[str, ...]:
    """Return the field names a request body carried, and nothing else.

    Understands JSON objects and form encoding, which is what a browser sends. A value
    is never read: it is not needed to describe an endpoint and a login's is a
    credential, so the only way to keep that promise is for no value to be reachable
    from what this returns.

    A body it cannot parse yields nothing rather than a guess.
    """
    if not body:
        return ()
    try:
        document = json.loads(body)
    except ValueError:
        document = None
    if isinstance(document, dict):
        return tuple(str(key) for key in document)
    if document is not None:
        return ()
    try:
        return tuple(dict.fromkeys(name for name, _ in parse_qsl(body, strict_parsing=True)))
    except ValueError:
        return ()


@dataclass(frozen=True, slots=True)
class ObservedRequest:
    """One request the application made of its own accord.

    ``carried_body`` rather than the body itself, and ``body_keys`` rather than the
    values under them. A login's body is a credential; the names of its fields are not,
    and they are what parameter testing needs to know. Nothing here can carry a value,
    which is what keeps an observation safe to write into evidence.
    """

    method: str
    url: str
    resource_type: str
    carried_body: bool
    body_keys: tuple[str, ...] = ()
    """The field names a body carried, never the values under them."""

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
                            body_keys=body_field_names(outgoing.post_data),
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
                    if request.login.open_selector is not None:
                        await page.locator(request.login.open_selector).first.click()
                        await page.wait_for_timeout(request.settle_ms)
                    await page.locator(request.login.username_selector).fill(
                        request.login.username.get_secret_value()
                    )
                    await page.locator(request.login.password_selector).fill(
                        request.login.password.get_secret_value()
                    )
                    await page.locator(request.login.submit_selector).click()
                    await page.wait_for_load_state("domcontentloaded")
                    # A single-page application signs in over XHR and never navigates,
                    # so the load state settles at once and the token has not been
                    # stored yet. Leaving here would navigate away mid-login and then
                    # observe an anonymous session that looks like a logged-in one.
                    await page.wait_for_timeout(request.settle_ms)
                    if request.login.continue_selector is not None:
                        await page.locator(request.login.continue_selector).first.click()
                        await page.wait_for_timeout(request.settle_ms)
                response = None
                if request.login is None or request.navigate_after_login:
                    response = await page.goto(
                        request.target, wait_until="domcontentloaded"
                    )
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
