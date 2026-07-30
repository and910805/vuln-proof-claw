"""Normalization and default-deny scope evaluation for Web/API targets."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from urllib.parse import unquote, urlsplit

from vuln_proof_claw.domain.errors import DomainValidationError

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_OCTET = re.compile(r"%[0-9A-Fa-f]{2}")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_MAX_PORT = 65_535


def normalize_hostname(value: str) -> str:
    """Normalize a DNS hostname or IP literal without resolving it."""
    candidate = value.strip().rstrip(".")
    if not candidate:
        raise DomainValidationError("hostname must not be empty")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise DomainValidationError("hostname is not valid IDNA") from error
    if len(normalized) > _MAX_HOSTNAME_LENGTH:
        raise DomainValidationError("hostname exceeds 253 characters")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > _MAX_LABEL_LENGTH
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise DomainValidationError("hostname contains an invalid label")
    return normalized


def normalize_network(value: str) -> IPNetwork:
    """Normalize an IPv4 or IPv6 network, accepting host bits."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise DomainValidationError("CIDR is invalid") from error


def normalize_port(value: int) -> int:
    """Validate a TCP/UDP port number."""
    if not 1 <= value <= _MAX_PORT:
        raise DomainValidationError("port must be between 1 and 65535")
    return value


def normalize_scheme(value: str) -> str:
    """Normalize a supported Web/API URL scheme."""
    scheme = value.strip().lower()
    if scheme not in _DEFAULT_PORTS:
        raise DomainValidationError("only http and https schemes are supported")
    return scheme


def normalize_path(value: str) -> str:
    """Decode and collapse a URL path for conservative scope comparison."""
    candidate = value or "/"
    if _INVALID_PERCENT.search(candidate):
        raise DomainValidationError("path contains invalid percent encoding")
    for _ in range(5):
        try:
            decoded = unquote(candidate, errors="strict")
        except UnicodeError as error:
            raise DomainValidationError("path contains invalid UTF-8 encoding") from error
        if decoded == candidate:
            break
        candidate = decoded
    if _ENCODED_OCTET.search(candidate):
        raise DomainValidationError("path contains excessive nested encoding")
    if _CONTROL_CHARACTER.search(candidate) or "\\" in candidate:
        raise DomainValidationError("path contains a control character or backslash")
    normalized = posixpath.normpath("/" + candidate.lstrip("/"))
    return normalized if normalized.startswith("/") else f"/{normalized}"


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """Canonical network target used by scope and approval policies."""

    scheme: str
    host: str
    port: int
    path: str

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"


def normalize_target(value: str) -> NormalizedTarget:
    """Normalize an absolute HTTP(S) URL and remove query/fragment data."""
    if _CONTROL_CHARACTER.search(value):
        raise DomainValidationError("target contains a control character")
    parsed = urlsplit(value)
    scheme = normalize_scheme(parsed.scheme)
    if parsed.username is not None or parsed.password is not None:
        raise DomainValidationError("target must not contain embedded credentials")
    if parsed.hostname is None:
        raise DomainValidationError("target must include a hostname")
    host = normalize_hostname(parsed.hostname)
    try:
        port = parsed.port or _DEFAULT_PORTS[scheme]
    except ValueError as error:
        raise DomainValidationError("target port is invalid") from error
    return NormalizedTarget(
        scheme=scheme,
        host=host,
        port=normalize_port(port),
        path=normalize_path(parsed.path),
    )


def _path_matches(path: str, prefix: str) -> bool:
    return prefix in ("/", path) or path.startswith(f"{prefix}/")


@dataclass(frozen=True, slots=True)
class EngagementScope:
    """Normalized allow and deny rules for one engagement."""

    allowed_hostnames: frozenset[str]
    allowed_networks: tuple[IPNetwork, ...]
    allowed_ports: frozenset[int]
    allowed_schemes: frozenset[str] = frozenset({"https"})
    allowed_paths: tuple[str, ...] = ("/",)
    denied_hostnames: frozenset[str] = frozenset()
    denied_networks: tuple[IPNetwork, ...] = ()
    denied_paths: tuple[str, ...] = ()
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @classmethod
    def create(  # noqa: PLR0913 - explicit security-rule fields prevent ambiguity
        cls,
        *,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
        allowed_ports: tuple[int, ...] = (443,),
        allowed_schemes: tuple[str, ...] = ("https",),
        allowed_paths: tuple[str, ...] = ("/",),
        denied_hostnames: tuple[str, ...] = (),
        denied_cidrs: tuple[str, ...] = (),
        denied_paths: tuple[str, ...] = (),
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> EngagementScope:
        """Create a scope after normalizing every comparison value."""
        if valid_from is not None and (valid_from.tzinfo is None or valid_from.utcoffset() is None):
            raise DomainValidationError("valid_from must be timezone-aware")
        if valid_until is not None and (
            valid_until.tzinfo is None or valid_until.utcoffset() is None
        ):
            raise DomainValidationError("valid_until must be timezone-aware")
        if valid_from is not None and valid_until is not None and valid_until <= valid_from:
            raise DomainValidationError("valid_until must be later than valid_from")
        return cls(
            allowed_hostnames=frozenset(normalize_hostname(item) for item in allowed_hostnames),
            allowed_networks=tuple(normalize_network(item) for item in allowed_cidrs),
            allowed_ports=frozenset(normalize_port(item) for item in allowed_ports),
            allowed_schemes=frozenset(normalize_scheme(item) for item in allowed_schemes),
            allowed_paths=tuple(normalize_path(item) for item in allowed_paths),
            denied_hostnames=frozenset(normalize_hostname(item) for item in denied_hostnames),
            denied_networks=tuple(normalize_network(item) for item in denied_cidrs),
            denied_paths=tuple(normalize_path(item) for item in denied_paths),
            valid_from=valid_from.astimezone(UTC) if valid_from else None,
            valid_until=valid_until.astimezone(UTC) if valid_until else None,
        )


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """Result of evaluating one normalized target against an engagement scope."""

    allowed: bool
    reason: str
    target: NormalizedTarget
    requires_dns_recheck: bool


def evaluate_scope(
    target: str | NormalizedTarget,
    scope: EngagementScope,
    *,
    at: datetime,
) -> ScopeDecision:
    """Evaluate deny rules before allow rules and default to denial."""
    if at.tzinfo is None or at.utcoffset() is None:
        raise DomainValidationError("at must be timezone-aware")
    normalized = normalize_target(target) if isinstance(target, str) else target
    requires_dns_recheck = not normalized.is_ip

    address: IPAddress | None
    try:
        address = ipaddress.ip_address(normalized.host)
    except ValueError:
        address = None
    host_allowed = normalized.host in scope.allowed_hostnames
    network_allowed = address is not None and any(
        address in network for network in scope.allowed_networks
    )
    allowed = False
    if scope.valid_from is not None and at < scope.valid_from:
        reason = "engagement_not_started"
    elif scope.valid_until is not None and at >= scope.valid_until:
        reason = "engagement_expired"
    elif normalized.scheme not in scope.allowed_schemes:
        reason = "scheme_not_allowed"
    elif normalized.port not in scope.allowed_ports:
        reason = "port_not_allowed"
    elif normalized.host in scope.denied_hostnames:
        reason = "hostname_denied"
    elif address is not None and any(address in network for network in scope.denied_networks):
        reason = "network_denied"
    elif any(_path_matches(normalized.path, prefix) for prefix in scope.denied_paths):
        reason = "path_denied"
    elif not host_allowed and not network_allowed:
        reason = "host_not_allowed"
    elif not any(_path_matches(normalized.path, prefix) for prefix in scope.allowed_paths):
        reason = "path_not_allowed"
    else:
        allowed = True
        reason = "scope_allowed"
    return ScopeDecision(allowed, reason, normalized, requires_dns_recheck)
