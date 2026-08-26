"""Map control-plane action types and observed commands to ATT&CK techniques.

The action-type keys are the same strings used by
:mod:`vuln_proof_claw.policy.risk`, so a command classified here also carries a
risk level and an approval requirement without a second taxonomy.

Every rule below was added because a naive version of it produced a wrong
answer on a real 632-command transcript:

* A tool counts only when the line looks like an invocation - the name at a
  command position, followed by a flag. Searching for the bare name counted
  mentions: a tool-inventory loop, a version check inside a setup script, even
  prose discussing the tool. Counting mentions is how a run gets credited with
  a scan it never performed.
* ``--version`` and ``--help`` are invocations but not actions, so they do not
  count either.
* Signatures describing what was sent are matched against the request - the
  URLs plus any ``--data`` argument - not the whole command line. Matching the
  line read ordinary wrapper syntax such as ``&& cat > script.sh`` as a
  shell-injection payload, and read a Python snippet building a traversal
  string as a traversal request.
* Shell injection is a parameter whose value carries a shell metacharacter,
  which is what it looks like on the wire.
* When the caller names the engagement's targets, commands mentioning none of
  them are not classified, because a coverage layer should only count actions
  aimed at the target.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from vuln_proof_claw.policy.risk import normalize_action_type

ATTACK_DOMAIN: Final = "enterprise-attack"

# A URL runs to the next space or quote. Shell metacharacters stay because an
# injection payload lives inside the query string.
_URL_TOKEN: Final = re.compile(r"https?://[^\s'\"]+")
# A request is not always written as a full URL. An agent that hits the limits
# of curl may write its own client, putting the host in code and passing only
# the path. A path carrying a query string is unambiguously a request.
_PATH_QUERY: Final = re.compile(r"/[^\s'\"]*\?[^\s'\"]+")
_QUOTED: Final = re.compile(r"'([^']*)'|\"([^\"]*)\"")
# Only the long forms. A bare -d appears in too many unrelated commands, and
# treating every quoted argument as a request body produced false traversals.
_BODY_FLAG: Final = re.compile(r"--data(?:-urlencode|-raw|-binary|-ascii)?\b|--form\b")


def _invocation(*names: str) -> re.Pattern[str]:
    """Build a pattern that matches running one of these tools, not naming it.

    The name must sit at a command position - start of line, after a shell
    separator, or at the end of a path - and be followed by a flag. Version and
    help flags are excluded: they prove the tool exists, not that it was used.
    """
    alternatives = "|".join(names)
    return re.compile(
        r"(?:^|[\s;&|(`/\\])"
        rf"(?:{alternatives})"
        r"(?:\.exe)?[\"']?"
        r"\s+(?!--?(?:version|help|h|v)\b)-"
    )


ACTION_TECHNIQUES: Final = MappingProxyType(
    {
        "public_page_read": ("T1594",),
        "robots_read": ("T1594",),
        "passive_fingerprint": ("T1592.002",),
        "passive_discovery": ("T1594",),
        "active_safe_api_read": ("T1594",),
        "directory_enumeration": ("T1595.003",),
        "port_scan": ("T1595.001",),
        "vulnerability_scan": ("T1595.002",),
        "active_api_probe": ("T1595",),
        "exploit_attempt": ("T1190",),
        "password_test": ("T1110.001",),
        "file_upload": ("T1505.003",),
        "post_exploitation": ("T1082",),
        "privilege_escalation": ("T1068",),
        "lateral_movement": ("T1210",),
        "data_modification": ("T1565",),
        "data_deletion": ("T1485",),
        "persistence": ("T1505.003",),
        "destructive_operation": ("T1499",),
    }
)

TECHNIQUE_NAMES: Final = MappingProxyType(
    {
        "T1059.004": "Command and Scripting Interpreter: Unix Shell",
        "T1068": "Exploitation for Privilege Escalation",
        "T1082": "System Information Discovery",
        "T1083": "File and Directory Discovery",
        "T1110.001": "Brute Force: Password Guessing",
        "T1190": "Exploit Public-Facing Application",
        "T1210": "Exploitation of Remote Services",
        "T1485": "Data Destruction",
        "T1499": "Endpoint Denial of Service",
        "T1499.002": "Endpoint DoS: Service Exhaustion Flood",
        "T1505.003": "Server Software Component: Web Shell",
        "T1552.001": "Unsecured Credentials: Credentials In Files",
        "T1565": "Data Manipulation",
        "T1592.002": "Gather Victim Host Information: Software",
        "T1594": "Search Victim-Owned Websites",
        "T1595": "Active Scanning",
        "T1595.001": "Active Scanning: Scanning IP Blocks",
        "T1595.002": "Active Scanning: Vulnerability Scanning",
        "T1595.003": "Active Scanning: Wordlist Scanning",
    }
)


@dataclass(frozen=True, slots=True)
class Classification:
    """One observed command mapped onto an action type and its techniques."""

    action_type: str
    techniques: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Signature:
    """One pattern, what it means, and what text it is allowed to match."""

    pattern: re.Pattern[str]
    action_type: str
    techniques: tuple[str, ...]
    # True: match the request only. False: match the whole command line.
    request_only: bool


_SIGNATURES: Final = (
    _Signature(
        re.compile(r"/etc/shadow|wp-config\.php|id_rsa|(?<![\w.])\.env(?![\w])"),
        "post_exploitation",
        ("T1552.001",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"/etc/passwd|\.\.(?:/|%2f|%252f)"),
        "post_exploitation",
        ("T1083",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"/proc/self/|/proc/version"),
        "post_exploitation",
        ("T1082",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"(?:^|[?&])[\w.\[\]-]+=[^&]*(?:[`;|]|%60|%3b|%7c)"),
        "exploit_attempt",
        ("T1190", "T1059.004"),
        request_only=True,
    ),
    _Signature(
        re.compile(r"wp-login\.php|[?&]log=|[?&]pwd="),
        "password_test",
        ("T1110.001",),
        request_only=True,
    ),
    _Signature(
        _invocation("hydra", "medusa", "patator"),
        "password_test",
        ("T1110.001",),
        request_only=False,
    ),
    _Signature(
        _invocation("sqlmap", "commix", "tplmap"),
        "exploit_attempt",
        ("T1190",),
        request_only=False,
    ),
    _Signature(
        _invocation("wpscan", "nuclei", "nikto", "wapiti", "jaeles", "dalfox"),
        "vulnerability_scan",
        ("T1595.002",),
        request_only=False,
    ),
    _Signature(
        _invocation("ffuf", "feroxbuster", "gobuster", "dirb", "dirsearch", "wfuzz", "x8"),
        "directory_enumeration",
        ("T1595.003",),
        request_only=False,
    ),
    _Signature(
        _invocation("nmap", "rustscan", "masscan", "naabu"),
        "port_scan",
        ("T1595.001",),
        request_only=False,
    ),
    _Signature(
        _invocation("httpx", "whatweb", "wappalyzer", "webanalyze"),
        "passive_fingerprint",
        ("T1592.002",),
        request_only=False,
    ),
    _Signature(
        _invocation("slowhttptest"),
        "destructive_operation",
        ("T1499.002",),
        request_only=False,
    ),
    _Signature(
        re.compile(r"xmlrpc\.php|load-scripts\.php|system\.multicall"),
        "destructive_operation",
        ("T1499.002",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"/robots\.txt|/sitemap(?:_index)?\.xml"),
        "robots_read",
        ("T1594",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"openapi\.json|/swagger|/\.well-known/|/graphql"),
        "passive_discovery",
        ("T1594",),
        request_only=True,
    ),
    _Signature(
        re.compile(r"^https?://"),
        "public_page_read",
        ("T1594",),
        request_only=True,
    ),
)


_ASSIGNMENT: Final = re.compile(
    r"(?<![\w-])([a-z_][a-z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))"
)


def expand_assignments(command: str) -> str:
    """Substitute simple shell variable assignments before looking for a tool.

    A Windows tool path is commonly assigned first and invoked as ``"$NMAP"``,
    which leaves the tool name nowhere near a flag. Expanding is only used when
    deciding whether a tool ran; request parsing still reads the original text.
    """
    values: dict[str, str] = {}
    for name, double, single, bare in _ASSIGNMENT.findall(command):
        values[name] = double or single or bare
    expanded = command
    for name, value in values.items():
        for form in (f'"${{{name}}}"', f'"${name}"', f"${{{name}}}", f"${name}"):
            expanded = expanded.replace(form, value)
    return expanded


def techniques_for_action(action_type: str) -> tuple[str, ...]:
    """Return the default techniques for a control-plane action type."""
    return ACTION_TECHNIQUES.get(normalize_action_type(action_type), ())


def request_parts(command: str) -> tuple[str, ...]:
    """Return the parts of a command that describe the request that was sent.

    The URLs, plus any quoted argument when a request-body flag is present. The
    payload is not always in the URL: ``curl --get --data-urlencode
    'host=127.0.0.1;id'`` puts it in an argument that curl appends later.
    """
    parts = list(_URL_TOKEN.findall(command))
    parts.extend(_PATH_QUERY.findall(command))
    if _BODY_FLAG.search(command):
        parts.extend(single or double for single, double in _QUOTED.findall(command))
    return tuple(part for part in parts if part)


def targets_the_engagement(command: str, targets: Sequence[str]) -> bool:
    """Return whether the command mentions one of the engagement's targets.

    Without this filter a transcript that also contains lab setup, container
    plumbing and file edits inflates every tactic it happens to resemble.
    """
    if not targets:
        return True
    usable = [target.strip().lower() for target in targets if target.strip()]
    if not usable:
        # Silently dropping every command would produce an empty layer that
        # reads as "the agent did nothing", the exact misreading this module
        # exists to prevent.
        raise ValueError("targets were given but none of them are usable")
    haystack = command.lower()
    return any(target in haystack for target in usable)


def classify_command(
    command: str,
    *,
    targets: Sequence[str] = (),
) -> Classification | None:
    """Classify one shell command, most specific signature first.

    Returns ``None`` when nothing matches, or when ``targets`` is given and the
    command mentions none of them, so the caller can report the command instead
    of silently dropping it.
    """
    if not command or not command.strip():
        return None
    if not targets_the_engagement(command, targets):
        return None
    haystack = command.lower()
    request = request_parts(haystack)
    invocations = expand_assignments(haystack)
    for signature in _SIGNATURES:
        if signature.request_only:
            if not any(signature.pattern.search(part) for part in request):
                continue
        elif not signature.pattern.search(invocations):
            continue
        return Classification(
            action_type=signature.action_type,
            techniques=signature.techniques,
        )
    return None
