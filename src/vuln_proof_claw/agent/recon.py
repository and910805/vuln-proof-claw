"""Recover a target's API inventory through the scope-enforcing transport.

:mod:`vuln_proof_claw.agent.jsdiscovery` parses bundles; this fetches them. Keeping the
two apart means the parser can be tested exhaustively without a network, and every byte
this module retrieves passes the same scope evaluation, DNS pinning and SSRF guard as
any other request the system makes.

The cost is bounded by construction: one request for the page, then at most
``maximum_assets`` for its scripts. A target with eighty lazy chunks is not fully
enumerated — the entry and shared bundles carry the application's own API layer, and
fetching the rest would turn reconnaissance into the kind of sweep the activity rules
forbid.

**Asset origins are not scope.** Many applications serve their own JavaScript from a
CDN that is not itself an authorized target, which leaves the code describing the
in-scope API sitting on an out-of-scope host. ``asset_origins`` names hosts whose
*static code may be read*, and it grants nothing else: the entry page must still be in
scope, only assets that page references are fetched, and no endpoint on such a host is
ever probed, recorded, or promoted to a lead. Reading a public script is what a browser
does when it loads the authorized page; testing the host that served it is a different
act, and the scope engine still decides that one alone.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urljoin

from vuln_proof_claw.agent.authsession import AuthenticatedTransport, ProbeLimits
from vuln_proof_claw.agent.endpoints import EndpointClassification, classify_all
from vuln_proof_claw.agent.htmldiscovery import extract_endpoints as extract_html_endpoints
from vuln_proof_claw.agent.htmldiscovery import inventory as html_inventory
from vuln_proof_claw.agent.jsdiscovery import (
    DiscoveredCall,
    extract_assets,
    extract_calls,
    extract_chunk_table,
    inventory,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope, normalize_target

_LOGGER = logging.getLogger(__name__)

_DEFAULT_MAX_ASSETS: Final = 8
#: An entry page commonly redirects once, to a locale prefix or a sign-in page. Two
#: allows for a chain; more than that is a loop or a target leading us somewhere.
_DEFAULT_MAX_REDIRECTS: Final = 2
_REDIRECT_MIN: Final = 300
_REDIRECT_MAX: Final = 399
_ASSET_LIMITS: Final = ProbeLimits(timeout_seconds=20, max_response_bytes=8 * 1024 * 1024)
_PAGE_LIMITS: Final = ProbeLimits(timeout_seconds=15, max_response_bytes=1024 * 1024)
_SUCCESS_MIN: Final = 200
_SUCCESS_MAX: Final = 299
_RUNTIME_HINT: Final = "runtime"
#: Names webpack and friends give the bundles that hold an application's own code.
#:
#: "chunk" is deliberately absent. Every file in a split build is named
#: ``<something>.chunk.js``, so including it matched all of them and the ranking
#: stopped distinguishing anything: a target whose API layer sat in
#: ``commons.<hash>.chunk.js`` had it tie with ``27.<hash>.chunk.js``, and the budget
#: went to whichever the chunk table happened to list first. A hint that matches
#: everything is not a hint. "shared" stays, because ``shared~<hash>.chunk.js`` names
#: a specific thing.
_SHARED_HINTS: Final = ("commons", "main", "index", "app", "shared", "vendors~")
#: How many requests an asset budget of N may spend before giving up, so a page whose
#: scripts all 404 cannot keep trying forever.
_ATTEMPT_ALLOWANCE: Final = 2


@dataclass(frozen=True, slots=True)
class Fetched:
    """One fetch attempt: the bytes, a redirect to follow, or why neither happened.

    The reason is carried rather than logged and discarded. "entry page could not be
    retrieved" and "HTTP 302 to /tw/" send an operator to completely different places,
    and only one of them is a dead end.
    """

    body: bytes | None = None
    redirect_to: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class FetchedAsset:
    """One script retrieved during reconnaissance."""

    url: str
    digest: str
    size: int


@dataclass(frozen=True, slots=True)
class ReconResult:
    """What one reconnaissance pass recovered."""

    base_url: str
    assets: tuple[FetchedAsset, ...] = ()
    calls: tuple[DiscoveredCall, ...] = ()
    classifications: tuple[EndpointClassification, ...] = ()
    errors: tuple[str, ...] = ()
    sent_at: tuple[datetime, ...] = ()
    """When each request left, including the ones that failed.

    Reconnaissance is bounded and paced, but bounded is not the same as unaccounted:
    a request that left the machine has to appear in the ledger, or the mission's own
    record of how much it touched the target is understated. The times are kept rather
    than a count, because a rate limit is answered by when requests were sent.
    """

    @property
    def requests_sent(self) -> int:
        return len(self.sent_at)

    @property
    def surface_digest(self) -> str:
        """A digest over the fetched bundles.

        A change here means the application was redeployed, which is the signal worth
        acting on: new endpoints appear on the day they ship, before anyone else has
        looked at them.
        """
        material = "\x1f".join(sorted(asset.digest for asset in self.assets))
        return hashlib.sha256(material.encode()).hexdigest()

    @property
    def probeable(self) -> tuple[EndpointClassification, ...]:
        return tuple(item for item in self.classifications if item.safe_to_probe)

    @property
    def held_back(self) -> tuple[EndpointClassification, ...]:
        return tuple(item for item in self.classifications if not item.safe_to_probe)


@dataclass
class SpaReconnaissance:
    """Fetch a single-page application's scripts and recover its API inventory."""

    transport: AuthenticatedTransport
    scope: EngagementScope
    base_url: str
    maximum_assets: int = _DEFAULT_MAX_ASSETS
    maximum_redirects: int = _DEFAULT_MAX_REDIRECTS
    session_headers: Callable[[], tuple[tuple[str, str], ...]] | None = None
    """Supplies the cookie header to look at the target as a logged-in identity.

    Without this, discovery sees only what an anonymous caller sees — which, on an
    application whose surface is behind a login, is the login page and nothing else.
    Called per request rather than captured once, so a session re-established between
    passes is picked up instead of a stale cookie being reused.
    """

    asset_origins: frozenset[str] = frozenset()
    """Hosts whose static code may be read although they are not authorized targets.

    Grants exactly one thing: fetching a script the in-scope entry page references.
    Never a probe target, never a lead.
    """
    user_agent: str = "vuln-proof-claw/recon"
    pacer: Callable[[float], None] | None = None
    interval_seconds: float = 2.0
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    _fetched: int = field(default=0, init=False, repr=False)
    _sent_at: list[datetime] = field(default_factory=list, init=False, repr=False)
    _asset_requests: int = field(default=0, init=False, repr=False)

    def discover(self, *, at: datetime | None = None) -> ReconResult:
        """Fetch the page and its scripts, then recover the API inventory."""
        moment = at or datetime.now(UTC)
        errors: list[str] = []
        started_with = len(self._sent_at)

        page = self._fetch(self.base_url, _PAGE_LIMITS, at=moment)
        if page.body is None:
            return ReconResult(
                base_url=self.base_url,
                errors=(f"entry page not retrieved — {page.reason}",),
                sent_at=tuple(self._sent_at[started_with:]),
            )

        html = page.body.decode("utf-8", errors="replace")
        wanted = self._prioritise(extract_assets(html).all)

        assets: list[FetchedAsset] = []
        sources: list[str] = []
        index = 0
        # The budget counts requests that were actually sent. An asset the scope
        # refuses costs nothing — no socket is opened — so letting it consume a slot
        # would spend the budget on scripts we never read. On a page referencing a
        # third-party error reporter before its own code, that is the whole budget.
        while index < len(wanted) and len(assets) < self.maximum_assets:
            relative = wanted[index]
            index += 1
            if self._asset_requests >= self.maximum_assets * _ATTEMPT_ALLOWANCE:
                errors.append("asset budget spent on failed fetches")
                break
            url = urljoin(self.base_url, relative)
            before = len(self._sent_at)
            fetched = self._fetch(url, _ASSET_LIMITS, at=moment, as_asset=True)
            self._asset_requests += len(self._sent_at) - before
            if fetched.body is None:
                errors.append(f"asset not retrieved: {relative} — {fetched.reason}")
                continue
            body = fetched.body
            text = body.decode("utf-8", errors="replace")
            assets.append(
                FetchedAsset(
                    url=url, digest=hashlib.sha256(body).hexdigest(), size=len(body)
                )
            )
            sources.append(text)

            if _RUNTIME_HINT in relative:
                extra = self._shared_chunks(text, relative)
                wanted = (*wanted, *extra)

        calls = extract_calls("\n".join(sources))
        recovered = inventory(calls)

        # An application that renders on the server describes no API in its JavaScript,
        # so the scripts yield nothing and the surface is in the markup instead: the
        # links it offers and the forms it posts. Read that too rather than reporting an
        # empty inventory for a target that plainly has one.
        from_markup = html_inventory(extract_html_endpoints(html, page_url=self.base_url))
        merged = (*recovered, *(item for item in from_markup if item not in recovered))

        return ReconResult(
            base_url=self.base_url,
            assets=tuple(assets),
            calls=calls,
            classifications=classify_all(merged),
            errors=tuple(errors),
            sent_at=tuple(self._sent_at[started_with:]),
        )

    @staticmethod
    def _prioritise(assets: tuple[str, ...]) -> tuple[str, ...]:
        """Order assets so the application's own code is fetched before libraries.

        With a bounded budget the order decides what is found. A runtime comes first
        because it names the lazy chunks; shared bundles next, since they hold the API
        layer; vendor bundles last, as they rarely contain target endpoints.
        """

        def rank(name: str) -> int:
            lowered = name.lower()
            if _RUNTIME_HINT in lowered:
                return 0
            if any(hint in lowered for hint in _SHARED_HINTS):
                return 1
            return 2

        return tuple(sorted(assets, key=rank))

    def _shared_chunks(self, runtime: str, relative: str) -> tuple[str, ...]:
        """Return lazy chunks worth fetching, named by the runtime's own table."""
        table = extract_chunk_table(runtime)
        if not table.entries:
            return ()
        directory = relative.rsplit("/", 1)[0] if "/" in relative else ""
        selected = [
            name
            for name in table.filenames()
            if any(hint in name.lower() for hint in _SHARED_HINTS)
        ]
        return tuple(f"{directory}/{name}" if directory else name for name in selected)

    def _fetch(
        self, url: str, limits: ProbeLimits, *, at: datetime, as_asset: bool = False
    ) -> Fetched:
        """Retrieve one URL, refusing anything the scope does not permit.

        Follows a redirect when it stays inside the authorized scope, up to
        ``maximum_redirects``. The transport still refuses to follow one itself: this
        re-evaluates the new location against the scope and issues a fresh request, so
        every address reached is one the engagement allows rather than one the target
        talked us into.
        """
        current = url
        for _ in range(self.maximum_redirects + 1):
            outcome = self._fetch_once(current, limits, at=at, as_asset=as_asset)
            if outcome.redirect_to is None:
                return outcome
            current = outcome.redirect_to
        return Fetched(reason=f"more than {self.maximum_redirects} redirects from {url}")

    def _permitted(self, target: str, *, as_asset: bool, at: datetime) -> str | None:
        """Return why this URL may not be fetched, or None if it may.

        An asset origin is consulted only after the scope has refused, and only for an
        asset. The entry page is never fetched on that basis, so the application being
        examined is always one the engagement authorizes — the origin list only says
        where that application's own code is allowed to live.
        """
        decision = evaluate_scope(target, self.scope, at=at)
        if decision.allowed:
            return None
        if as_asset and normalize_target(target).host in self.asset_origins:
            _LOGGER.info("reading asset from permitted origin: %s", target)
            return None
        return f"refused by scope ({decision.reason}): {target}"

    def _fetch_once(  # noqa: PLR0911 - one return per distinct outcome, each named
        self, url: str, limits: ProbeLimits, *, at: datetime, as_asset: bool = False
    ) -> Fetched:
        """Send exactly one request and say plainly what came back."""
        try:
            target = str(normalize_target(url))
        except DomainValidationError:
            return Fetched(reason=f"not a valid URL: {url}")

        refusal = self._permitted(target, as_asset=as_asset, at=at)
        if refusal is not None:
            return Fetched(reason=refusal)

        if self._fetched:
            self._pace()
        self._fetched += 1
        self._sent_at.append(self.clock())
        try:
            # An asset origin is a third party, so the session cookie is withheld
            # there: it has no business leaving the application it belongs to.
            supplier = self.session_headers
            carry_session = (
                supplier is not None
                and normalize_target(target).host not in self.asset_origins
            )
            session = supplier() if supplier is not None and carry_session else ()
            response = self.transport.send(
                "GET",
                url,
                headers=(
                    ("accept", "*/*"),
                    ("user-agent", self.user_agent),
                    *session,
                ),
                body=None,
                limits=limits,
            )
        except Exception as error:  # noqa: BLE001 - one bad asset must not end recon
            _LOGGER.warning("recon fetch failed for %s: %s", url, error)
            return Fetched(reason=f"{type(error).__name__}: {str(error)[:120]}")

        if _REDIRECT_MIN <= response.status_code <= _REDIRECT_MAX:
            location = next(
                (value for name, value in response.headers if name.lower() == "location"),
                "",
            )
            if not location:
                return Fetched(reason=f"HTTP {response.status_code} with no location")
            return Fetched(redirect_to=urljoin(url, location))

        if not _SUCCESS_MIN <= response.status_code <= _SUCCESS_MAX:
            return Fetched(reason=f"HTTP {response.status_code}")
        return Fetched(body=response.body)

    def _pace(self) -> None:
        if self.pacer is not None:
            self.pacer(self.interval_seconds)
            return
        time.sleep(self.interval_seconds)


__all__ = ["FetchedAsset", "ReconResult", "SpaReconnaissance"]
