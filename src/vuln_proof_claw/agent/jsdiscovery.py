"""Recover an API inventory from a single-page application's own JavaScript.

A modern SPA ships its entire API surface to the browser. The bundle is public, served
to anyone who loads the page, and reading it is ordinary client-side code review — the
application hands it over as part of normal operation.

That makes it the highest-value, lowest-impact reconnaissance available: one request
per asset yields the endpoint list, with no probing of the API itself.

Everything here is pure parsing over text already fetched. This module performs no
network I/O, so it cannot reach a target and cannot exceed a rate limit; the caller
fetches assets through the scope-enforcing transport and passes the text in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

_SCRIPT_SRC: Final = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_MODULE_PRELOAD: Final = re.compile(
    r"""<link[^>]+rel\s*=\s*["']modulepreload["'][^>]+href\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

#: {url:"/api/x",method:"post"} — the axios-wrapper shape. The url group deliberately
#: swallows any trailing .concat(...) so the interpolation can be recovered rather than
#: silently dropped: a path built by concatenation is exactly the parameterised kind
#: worth surfacing.
_CALL_OBJECT: Final = re.compile(
    r"""\{\s*url\s*:\s*(?P<url>[`"'][^`"']{2,160}[`"']"""
    r"""(?:\s*\.concat\([^)]{0,240}\))?)\s*,\s*method\s*:\s*[`"'](?P<method>\w+)[`"']"""
)
_STRING_LITERAL: Final = re.compile(r"""[`"']([^`"']*)[`"']""")

#: .get("/api/x"  /  .post(`/api/x/${id}`
_CALL_METHOD: Final = re.compile(
    r"""\.(?P<method>get|post|put|delete|patch|head)\(\s*(?P<url>[`"'][/][^`"']{1,160}[`"'])""",
    re.IGNORECASE,
)

#: Webpack's lazy-chunk filename table, so the caller knows what else to fetch.
#: A runtime holds two maps keyed by the same chunk ids — names, then content hashes.
#: The name pattern excludes a long hex run, or every name would be overwritten by the
#: hash that shares its key.
_CHUNK_NAMES: Final = re.compile(
    r"(\d+)\s*:\s*[\"'](?![0-9a-f]{16,}[\"'])([A-Za-z0-9_-]{3,40})[\"']"
)
_CHUNK_HASHES: Final = re.compile(r"(\d+)\s*:\s*[\"']([0-9a-f]{16,32})[\"']")
_CHUNK_SUFFIX: Final = re.compile(r"""\}\[\w+\]\s*\+\s*["']((?:\.[A-Za-z]+){1,3})["']""")

_TEMPLATE_PARAM: Final = re.compile(r"\$\{[^}]{0,80}\}")
_MAX_PATH_LENGTH: Final = 160


@dataclass(frozen=True, slots=True)
class DiscoveredCall:
    """One API call recovered from client-side code."""

    method: str
    path: str

    @property
    def parameterised(self) -> bool:
        """Return whether the path interpolates a value, making it an IDOR candidate."""
        return "{param}" in self.path


@dataclass(frozen=True, slots=True)
class DiscoveredAssets:
    """Scripts a page references, as relative or absolute URLs."""

    scripts: tuple[str, ...] = ()
    preloads: tuple[str, ...] = ()

    @property
    def all(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.scripts, *self.preloads)))


@dataclass(frozen=True, slots=True)
class ChunkTable:
    """A webpack lazy-chunk map, recovered from the runtime bundle."""

    suffix: str = ".js"
    entries: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def filenames(self) -> tuple[str, ...]:
        """Return the filenames the application may load on demand."""
        return tuple(f"{name}.{digest}{self.suffix}" for name, digest in self.entries)


def extract_assets(html: str) -> DiscoveredAssets:
    """Find the scripts a page loads, including module preloads."""
    return DiscoveredAssets(
        scripts=tuple(dict.fromkeys(_SCRIPT_SRC.findall(html))),
        preloads=tuple(dict.fromkeys(_MODULE_PRELOAD.findall(html))),
    )


def _normalise_path(raw: str) -> str | None:
    """Reduce a path expression to a comparable template.

    Both interpolation styles collapse to the same marker, so a path assembled by
    template literal and one assembled by ``.concat()`` are recognised as the same
    shape. Without this, every webpack-built path would look like a static route and
    no IDOR candidate would ever be surfaced.
    """
    if ".concat(" in raw:
        literals = _STRING_LITERAL.findall(raw.split(".concat(", 1)[0]) + _STRING_LITERAL.findall(
            raw.split(".concat(", 1)[1]
        )
        if not literals:
            return None
        inner = "{param}".join(literals) if len(literals) > 1 else f"{literals[0]}{{param}}"
    else:
        inner = raw.strip("`\"'")

    if not inner.startswith("/"):
        return None
    collapsed = _TEMPLATE_PARAM.sub("{param}", inner)
    if "${" in collapsed or len(collapsed) > _MAX_PATH_LENGTH:
        return None
    return collapsed


def extract_calls(source: str) -> tuple[DiscoveredCall, ...]:
    """Recover method and path pairs from a bundle.

    Both common shapes are matched: a request-config object carrying ``url`` and
    ``method``, and a direct ``.get(...)`` style call. Results are deduplicated and
    sorted so a sweep over them is reproducible.
    """
    found: set[tuple[str, str]] = set()
    for pattern in (_CALL_OBJECT, _CALL_METHOD):
        for match in pattern.finditer(source):
            path = _normalise_path(match.group("url"))
            if path is not None:
                found.add((match.group("method").upper(), path))
    return tuple(
        DiscoveredCall(method=method, path=path) for method, path in sorted(found)
    )


def extract_chunk_table(runtime: str) -> ChunkTable:
    """Recover the lazy-chunk filename table from a webpack runtime.

    The application's own code usually lives in these chunks rather than in the entry
    bundle, so without this the recovered inventory is mostly third-party library code.
    """
    names = dict(_CHUNK_NAMES.findall(runtime))
    hashes = _CHUNK_HASHES.findall(runtime)
    if not hashes:
        return ChunkTable()
    suffix_match = _CHUNK_SUFFIX.search(runtime)
    suffix = suffix_match.group(1) if suffix_match else ".js"
    entries = tuple(
        (names.get(chunk_id, chunk_id), digest) for chunk_id, digest in hashes
    )
    return ChunkTable(suffix=suffix, entries=entries)


def inventory(calls: tuple[DiscoveredCall, ...]) -> tuple[tuple[str, str], ...]:
    """Return the (method, path) pairs in the shape the classifier expects."""
    return tuple((call.method, call.path) for call in calls)


def parameterised(calls: tuple[DiscoveredCall, ...]) -> tuple[DiscoveredCall, ...]:
    """Return the calls whose path interpolates a value.

    These are where a server-side ownership check is most often missing, so they are
    worth surfacing separately from the rest of the inventory.
    """
    return tuple(call for call in calls if call.parameterised)


__all__ = [
    "ChunkTable",
    "DiscoveredAssets",
    "DiscoveredCall",
    "extract_assets",
    "extract_calls",
    "extract_chunk_table",
    "inventory",
    "parameterised",
]
