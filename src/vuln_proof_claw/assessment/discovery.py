"""Deterministic, bounded URL discovery from captured HTTP responses."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import urljoin

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse
from vuln_proof_claw.policy.scope import NormalizedTarget, normalize_target

DiscoveryKind = Literal["link", "asset", "form", "sitemap", "javascript", "conventional"]

_SITEMAP_LOCATION = re.compile(r"<loc\b[^>]*>(.*?)</loc\s*>", re.IGNORECASE | re.DOTALL)
_ROBOTS_SITEMAP = re.compile(r"^\s*sitemap\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_JAVASCRIPT_URL = re.compile(
    r"[\"']((?:https?://[^\"'\s]+|/[^\"'\s]+?)(?:\.json|\.xml|/api(?:/[^\"'\s]*)?|/graphql))"
)
_CONVENTIONAL_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
)


@dataclass(frozen=True, slots=True)
class DiscoveredTarget:
    """One normalized same-origin URL with traceable discovery provenance."""

    url: str
    kind: DiscoveryKind
    source: str


@dataclass(frozen=True, slots=True)
class DiscoveryPreset:
    """Hard request/page/time budgets for a user-facing crawl preset."""

    name: Literal["safe", "fast", "deep"]
    page_budget: int
    request_budget: int
    time_budget_seconds: int
    include_conventional: bool


DISCOVERY_PRESETS = {
    "safe": DiscoveryPreset("safe", 5, 5, 20, False),
    "fast": DiscoveryPreset("fast", 15, 15, 45, True),
    "deep": DiscoveryPreset("deep", 30, 30, 90, True),
}


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, DiscoveryKind]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value}
        if tag.lower() in {"a", "area"} and values.get("href"):
            self.references.append((values["href"], "link"))
        elif tag.lower() in {"script", "img", "iframe", "source", "link"}:
            reference = values.get("src") or values.get("href")
            if reference:
                self.references.append((reference, "asset"))
        elif tag.lower() == "form" and values.get("action"):
            self.references.append((values["action"], "form"))


def _same_origin(candidate: NormalizedTarget, origin: NormalizedTarget) -> bool:
    return (
        candidate.scheme == origin.scheme
        and candidate.host == origin.host
        and candidate.port == origin.port
    )


def _normalize_reference(
    reference: str,
    *,
    base: str,
    origin: NormalizedTarget,
) -> str | None:
    value = html.unescape(reference).strip()
    if not value or value.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    try:
        normalized = normalize_target(urljoin(base, value))
    except DomainValidationError:
        return None
    return str(normalized) if _same_origin(normalized, origin) else None


def discover_targets(
    target: str,
    response: HttpCaptureResponse,
    *,
    include_conventional: bool = False,
    max_targets: int = 200,
) -> tuple[DiscoveredTarget, ...]:
    """Extract unique same-origin targets without initiating network activity."""
    if max_targets < 1:
        raise ValueError("max_targets must be positive")
    origin = normalize_target(target)
    base = str(normalize_target(response.final_target))
    headers = {name.lower(): value.lower() for name, value in response.headers}
    content_type = headers.get("content-type", "")
    text = response.body.decode("utf-8", errors="replace")
    references: list[tuple[str, DiscoveryKind]] = []

    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        parser = _PageParser()
        parser.feed(text)
        references.extend(parser.references)
    if "xml" in content_type or response.final_target.endswith((".xml", "/sitemap")):
        references.extend((match, "sitemap") for match in _SITEMAP_LOCATION.findall(text))
    if response.final_target.endswith("/robots.txt") or "text/plain" in content_type:
        references.extend((match, "sitemap") for match in _ROBOTS_SITEMAP.findall(text))
    if "javascript" in content_type or response.final_target.endswith(".js"):
        references.extend((match, "javascript") for match in _JAVASCRIPT_URL.findall(text))
    if include_conventional:
        references.extend((path, "conventional") for path in _CONVENTIONAL_PATHS)

    result: list[DiscoveredTarget] = []
    seen = {str(origin)}
    for reference, kind in references:
        normalized = _normalize_reference(reference, base=base, origin=origin)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        result.append(DiscoveredTarget(url=normalized, kind=kind, source=base))
        if len(result) >= max_targets:
            break
    return tuple(result)
