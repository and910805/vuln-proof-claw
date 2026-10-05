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
_ASSET_LIMITS: Final = ProbeLimits(timeout_seconds=20, max_response_bytes=8 * 1024 * 1024)
_PAGE_LIMITS: Final = ProbeLimits(timeout_seconds=15, max_response_bytes=1024 * 1024)
_SUCCESS_MIN: Final = 200
_SUCCESS_MAX: Final = 299
_RUNTIME_HINT: Final = "runtime"
_SHARED_HINTS: Final = ("commons", "main", "index", "app")


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
    user_agent: str = "vuln-proof-claw/recon"
    pacer: Callable[[float], None] | None = None
    interval_seconds: float = 2.0
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    _fetched: int = field(default=0, init=False, repr=False)
    _sent_at: list[datetime] = field(default_factory=list, init=False, repr=False)

    def discover(self, *, at: datetime | None = None) -> ReconResult:
        """Fetch the page and its scripts, then recover the API inventory."""
        moment = at or datetime.now(UTC)
        errors: list[str] = []
        started_with = len(self._sent_at)

        page = self._fetch(self.base_url, _PAGE_LIMITS, at=moment)
        if page is None:
            return ReconResult(
                base_url=self.base_url,
                errors=("entry page could not be retrieved",),
                sent_at=tuple(self._sent_at[started_with:]),
            )

        html = page.decode("utf-8", errors="replace")
        wanted = self._prioritise(extract_assets(html).all)

        assets: list[FetchedAsset] = []
        sources: list[str] = []
        for relative in wanted[: self.maximum_assets]:
            url = urljoin(self.base_url, relative)
            body = self._fetch(url, _ASSET_LIMITS, at=moment)
            if body is None:
                errors.append(f"asset not retrieved: {relative}")
                continue
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
        return ReconResult(
            base_url=self.base_url,
            assets=tuple(assets),
            calls=calls,
            classifications=classify_all(inventory(calls)),
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

    def _fetch(self, url: str, limits: ProbeLimits, *, at: datetime) -> bytes | None:
        """Retrieve one URL, refusing anything the scope does not permit."""
        try:
            target = str(normalize_target(url))
        except DomainValidationError:
            _LOGGER.warning("recon target is not a valid URL: %s", url)
            return None

        decision = evaluate_scope(target, self.scope, at=at)
        if not decision.allowed:
            _LOGGER.warning("recon target refused by scope: %s (%s)", url, decision.reason)
            return None

        if self._fetched:
            self._pace()
        self._fetched += 1
        self._sent_at.append(self.clock())
        try:
            response = self.transport.send(
                "GET",
                url,
                headers=(("accept", "*/*"), ("user-agent", self.user_agent)),
                body=None,
                limits=limits,
            )
        except Exception as error:  # noqa: BLE001 - one bad asset must not end recon
            _LOGGER.warning("recon fetch failed for %s: %s", url, error)
            return None
        if not _SUCCESS_MIN <= response.status_code <= _SUCCESS_MAX:
            _LOGGER.info("recon fetch returned %d for %s", response.status_code, url)
            return None
        return response.body

    def _pace(self) -> None:
        if self.pacer is not None:
            self.pacer(self.interval_seconds)
            return
        time.sleep(self.interval_seconds)


__all__ = ["FetchedAsset", "ReconResult", "SpaReconnaissance"]
