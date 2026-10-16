"""Recover a target's surface by watching a browser use it.

Satisfies the same ``Reconnaissance`` protocol as
:class:`~vuln_proof_claw.agent.recon.SpaReconnaissance`, so the mission loop treats it
identically: whatever it recovers goes to the endpoint classifier, and the classifier
alone decides what may be called.

The difference is where the paths come from. Reading a bundle recovers the strings an
application was *written* with, and those are not always the strings it *sends*: on one
live target every path in the JavaScript was missing the ``/api`` prefix the client
prepends at run time, so a sweep built from them would have probed a hundred and
ninety-five endpoints that do not exist, had every one suppressed as "no handler
reached", and reported a clean result for a surface it never touched. A wrong negative
that looks tidy is worse than a crash, because nothing asks you to go back and check.

An observed request carries no such gap. It is what left the browser.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vuln_proof_claw.agent.endpoints import classify_all
from vuln_proof_claw.agent.recon import ReconResult
from vuln_proof_claw.automation.browser import (
    BrowserRunRequest,
    IsolatedBrowserRunner,
    LoginInstruction,
    inventory,
)
from vuln_proof_claw.policy.scope import EngagementScope, normalize_target

_LOGGER = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_MS = 30_000
_DEFAULT_SETTLE_MS = 6_000


@dataclass
class BrowserReconnaissance:
    """Drive one bounded browser visit and classify what the application requested."""

    scope: EngagementScope
    base_url: str
    timeout_ms: int = _DEFAULT_TIMEOUT_MS
    settle_ms: int = _DEFAULT_SETTLE_MS
    ignore_https_errors: bool = False
    login: LoginInstruction | None = None
    """Sign in through the page before observing.

    Unauthenticated, a browser sees whatever the login screen itself fetches — on one
    target, three endpoints out of a surface of two hundred. The application only
    *uses* its API once someone is logged in, and using it is the whole point of
    watching. The credential lives in the instruction as a secret and reaches only the
    browser's own form fill; nothing here reads it, logs it, or records it.
    """

    runner: IsolatedBrowserRunner = field(default_factory=IsolatedBrowserRunner)

    def discover(self, *, at: datetime | None = None) -> ReconResult:
        """Visit the target once and report the surface it used.

        The protocol is synchronous and the browser is not, so the event loop is owned
        here. A failure is returned as an error rather than raised: the mission loop
        already treats a lost reconnaissance pass as a delay, and a browser is the part
        most likely to be missing, mis-installed, or slow.
        """
        moment = at or datetime.now(UTC)
        try:
            request = self._request()
        except Exception as error:  # noqa: BLE001 - a bad request is a reported error
            return ReconResult(base_url=self.base_url, errors=(str(error),))

        try:
            result = asyncio.run(self.runner.run(request))
        except Exception as error:  # noqa: BLE001 - recon must not fail the cycle
            _LOGGER.warning("browser reconnaissance failed: %s", error)
            return ReconResult(
                base_url=self.base_url,
                errors=(f"{type(error).__name__}: {str(error)[:160]}",),
            )

        observed = result.api_requests
        errors: list[str] = []
        if result.truncated_requests:
            # An inventory cut short looks exactly like a small surface, so this is
            # reported rather than left to be inferred from a count that seems low.
            errors.append(
                f"visit stopped after {len(result.observed_requests)} request(s); "
                f"{result.truncated_requests} more were refused by the per-visit ceiling"
            )
        if result.blocked_requests:
            # Reported, not silently dropped: a page reaching outside the engagement is
            # worth an operator knowing about even though the browser refused it.
            distinct = sorted(set(result.blocked_requests))
            errors.append(
                f"{len(distinct)} out-of-scope request(s) blocked, first: {distinct[0][:120]}"
            )

        return ReconResult(
            base_url=result.final_url or self.base_url,
            source="observed",
            classifications=classify_all(inventory(observed)),
            errors=tuple(errors),
            sent_at=tuple(
                request.sent_at or moment for request in result.observed_requests
            ),
        )

    def _request(self) -> BrowserRunRequest:
        parsed = normalize_target(self.base_url)
        hosts = set(self.scope.allowed_hostnames)
        # A scope written as a CIDR names no hostnames. The target's own host is
        # already inside it — the engagement definition is what allowed this URL — so
        # taking it here widens nothing.
        hosts.add(parsed.host)
        return BrowserRunRequest(
            target=self.base_url,
            allowed_hosts=frozenset(hosts),
            allowed_ports=frozenset(self.scope.allowed_ports or (443,)),
            login=self.login,
            timeout_ms=self.timeout_ms,
            settle_ms=self.settle_ms,
            ignore_https_errors=self.ignore_https_errors,
        )


__all__ = ["BrowserReconnaissance"]
