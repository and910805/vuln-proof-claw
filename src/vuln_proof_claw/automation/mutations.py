"""Typed, reviewable and digest-bound request mutation plans.

The built-in strategies intentionally use benign markers and boundary values. They are
designed to expose validation differences without shipping exploit payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vuln_proof_claw.domain.errors import DomainValidationError

_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_HEADERS = frozenset({"accept-language", "content-type", "x-requested-with"})
_MAX_REPLACEMENT_LENGTH = 256
_MAX_MUTATIONS = 8


class MutationLocation(StrEnum):
    QUERY = "query"
    HEADER = "header"
    PATH = "path"


class MutationStrategy(StrEnum):
    EMPTY = "empty"
    BOUNDARY = "boundary"
    TYPE_MISMATCH = "type_mismatch"
    BENIGN_MARKER = "benign_marker"


@dataclass(frozen=True, slots=True)
class MutationSpec:
    location: MutationLocation
    name: str
    strategy: MutationStrategy
    original_value: str | None = None
    replacement_value: str | None = None

    def __post_init__(self) -> None:
        normalized = self.name.strip()
        if not _TOKEN.fullmatch(normalized):
            raise DomainValidationError("mutation parameter name is invalid")
        object.__setattr__(self, "name", normalized)
        if self.location is MutationLocation.HEADER and normalized.lower() not in _SAFE_HEADERS:
            raise DomainValidationError(f"header mutation is not reviewed: {normalized.lower()}")
        if (
            self.replacement_value is not None
            and len(self.replacement_value) > _MAX_REPLACEMENT_LENGTH
        ):
            raise DomainValidationError("mutation replacement exceeds 256 characters")

    @property
    def effective_value(self) -> str:
        if self.replacement_value is not None:
            return self.replacement_value
        return {
            MutationStrategy.EMPTY: "",
            MutationStrategy.BOUNDARY: "2147483647",
            MutationStrategy.TYPE_MISMATCH: "proofclaw-text",
            MutationStrategy.BENIGN_MARKER: "proofclaw-validation-marker",
        }[self.strategy]


@dataclass(frozen=True, slots=True)
class MutationPlan:
    target: str
    mutations: tuple[MutationSpec, ...]
    reviewed_by: str
    review_reason: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DomainValidationError("mutation target must be an absolute HTTP URL")
        if not self.mutations:
            raise DomainValidationError("mutation plan must contain at least one mutation")
        if len(self.mutations) > _MAX_MUTATIONS:
            raise DomainValidationError("mutation plan exceeds eight mutations")
        if not self.reviewed_by.strip() or not self.review_reason.strip():
            raise DomainValidationError("mutation plan requires reviewer identity and reason")

    def canonical_document(self) -> dict[str, object]:
        return {
            "target": self.target,
            "mutations": [
                {
                    "location": item.location,
                    "name": item.name,
                    "strategy": item.strategy,
                    "original_value": item.original_value,
                    "replacement_value": item.replacement_value,
                }
                for item in self.mutations
            ],
            "reviewed_by": self.reviewed_by,
            "review_reason": self.review_reason,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_document(), sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    def apply(self, headers: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
        parsed = urlsplit(self.target)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        path_parts = parsed.path.split("/")
        output_headers = {key.lower(): value for key, value in (headers or {}).items()}
        for mutation in self.mutations:
            value = mutation.effective_value
            if mutation.location is MutationLocation.QUERY:
                query[mutation.name] = value
            elif mutation.location is MutationLocation.HEADER:
                output_headers[mutation.name.lower()] = value
            else:
                replaced = False
                for index, part in enumerate(path_parts):
                    if part == mutation.original_value:
                        path_parts[index] = value
                        replaced = True
                        break
                if not replaced:
                    raise DomainValidationError(
                        f"path value was not found for mutation: {mutation.name}"
                    )
        target = urlunsplit(
            (parsed.scheme, parsed.netloc, "/".join(path_parts), urlencode(query), "")
        )
        return target, output_headers
