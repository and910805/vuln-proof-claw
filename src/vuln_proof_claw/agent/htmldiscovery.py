"""Recover a server-rendered application's request surface from its own HTML.

:mod:`vuln_proof_claw.agent.jsdiscovery` reads the JavaScript of a single-page
application to find the API it calls. That finds nothing on an application that renders
on the server, because there is no API described in the client: the surface is the set
of links the pages offer and the forms they post.

This reads that surface instead. A link is a GET, a form is whatever method it declares,
and both carry the path the browser would actually request. Nothing here fetches
anything — it is a parser, so it can be tested exhaustively without a network, and the
component that decides what may be *called* remains the endpoint classifier.

Only same-origin, in-application references are returned. An anchor to another site is
somebody else's surface, and a ``mailto:`` or ``javascript:`` target is not a request
at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

_FORM = re.compile(r"<form\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_ANCHOR = re.compile(r"<a\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_ATTR = re.compile(r"""(\w[\w-]*)\s*=\s*["']([^"']*)["']""")

#: References that never produce an HTTP request to the application.
_NON_REQUEST = ("javascript:", "mailto:", "tel:", "data:", "#")

#: Methods a form may declare. Anything else is a typo or a framework override, and
#: assuming POST for an unknown value would invent a state change that was never there.
_FORM_METHODS = frozenset({"GET", "POST"})


@dataclass(frozen=True, slots=True)
class HtmlEndpoint:
    """One request the page offers, as the browser would make it."""

    method: str
    path: str
    origin: str
    """Whether this came from a ``form`` or an ``a`` element, for an operator reading
    the inventory: a form is a deliberate action, a link is navigation."""


def _attrs(text: str) -> dict[str, str]:
    return {key.lower(): value for key, value in _ATTR.findall(text)}


def _resolve(reference: str, *, page_url: str) -> str | None:
    """Return the same-origin path a reference requests, or None.

    Resolution is relative to the page, because ``index.php`` on ``/admin/`` is
    ``/admin/index.php`` and treating it as ``/index.php`` would probe a different
    endpoint and attribute the answer to the wrong one.
    """
    candidate = reference.strip()
    if not candidate or candidate.lower().startswith(_NON_REQUEST):
        return None

    absolute = urljoin(page_url, candidate)
    page = urlsplit(page_url)
    parsed = urlsplit(absolute)
    if (parsed.scheme, parsed.netloc) != (page.scheme, page.netloc):
        return None

    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def extract_endpoints(html: str, *, page_url: str) -> tuple[HtmlEndpoint, ...]:
    """Return the requests a page offers, in document order and deduplicated."""
    found: list[HtmlEndpoint] = []
    seen: set[tuple[str, str]] = set()

    for match in _FORM.finditer(html):
        attributes = _attrs(match.group("attrs"))
        # A form with no action posts back to the page it is on.
        target = attributes.get("action", page_url)
        method = attributes.get("method", "GET").upper()
        if method not in _FORM_METHODS:
            method = "GET"
        path = _resolve(target, page_url=page_url)
        if path is None or (method, path) in seen:
            continue
        seen.add((method, path))
        found.append(HtmlEndpoint(method=method, path=path, origin="form"))

    for match in _ANCHOR.finditer(html):
        href = _attrs(match.group("attrs")).get("href")
        if href is None:
            continue
        path = _resolve(href, page_url=page_url)
        if path is None or ("GET", path) in seen:
            continue
        seen.add(("GET", path))
        found.append(HtmlEndpoint(method="GET", path=path, origin="link"))

    return tuple(found)


def inventory(endpoints: tuple[HtmlEndpoint, ...]) -> tuple[tuple[str, str], ...]:
    """Reduce to the (method, path) pairs the endpoint classifier takes."""
    return tuple((endpoint.method, endpoint.path) for endpoint in endpoints)


__all__ = ["HtmlEndpoint", "extract_endpoints", "inventory"]
