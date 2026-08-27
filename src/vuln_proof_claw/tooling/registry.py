"""Built-in security-tool catalog with honest integration state."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from vuln_proof_claw.domain.enums import RiskLevel


class IntegrationState(StrEnum):
    """How far a tool has progressed from catalog entry to bounded execution."""

    CATALOGED = "cataloged"
    CONTRACT_READY = "contract_ready"
    WORKER_READY = "worker_ready"


class ToolManifest(BaseModel):
    """Immutable metadata exposed to the API, MCP clients, and planners."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    category: str
    capability: str
    action_type: str
    risk_level: RiskLevel
    integration_state: IntegrationState
    executable: str | None = None
    installed: bool | None = None
    requires_approval: bool
    description: str


def _manifest(  # noqa: PLR0913, PLR0917 - compact declaration helper
    name: str,
    category: str,
    action_type: str,
    risk: RiskLevel,
    state: IntegrationState,
    description: str,
    *,
    executable: str | None = None,
) -> ToolManifest:
    return ToolManifest(
        name=name,
        category=category,
        capability=name,
        action_type=action_type,
        risk_level=risk,
        integration_state=state,
        executable=executable,
        requires_approval=risk.requires_approval,
        description=description,
    )


_TOOLS = (
    _manifest(
        "shell_command",
        "runtime",
        "restricted_shell",
        RiskLevel.L2,
        IntegrationState.WORKER_READY,
        "Exact argv command execution inside a disposable restricted Worker.",
        executable="sh",
    ),
    _manifest(
        "python_execute",
        "runtime",
        "isolated_python",
        RiskLevel.L2,
        IntegrationState.WORKER_READY,
        "Bounded Python execution inside a disposable network-restricted Worker.",
        executable="python",
    ),
    _manifest(
        "nmap",
        "recon",
        "port_scan",
        RiskLevel.L1,
        IntegrationState.WORKER_READY,
        "Typed TCP connect scan with bounded ports, scripts, retries, and duration.",
        executable="nmap",
    ),
    _manifest(
        "password_test",
        "validation",
        "password_test",
        RiskLevel.L2,
        IntegrationState.CONTRACT_READY,
        "Rate-limited credential validation using external secret references.",
    ),
    _manifest(
        "exploit_poc",
        "validation",
        "exploit_attempt",
        RiskLevel.L2,
        IntegrationState.CONTRACT_READY,
        "Digest-pinned, non-destructive exploit or PoC validation.",
    ),
    _manifest(
        "httpx",
        "recon",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "HTTP service probing and technology discovery.",
        executable="httpx",
    ),
    _manifest(
        "nuclei",
        "scanner",
        "exploit_attempt",
        RiskLevel.L2,
        IntegrationState.CATALOGED,
        "Template-driven vulnerability and misconfiguration checks.",
        executable="nuclei",
    ),
    _manifest(
        "nikto",
        "scanner",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Web server configuration and known-file checks.",
        executable="nikto",
    ),
    _manifest(
        "ffuf",
        "discovery",
        "directory_enumeration",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Rate-bounded content and parameter discovery.",
        executable="ffuf",
    ),
    _manifest(
        "feroxbuster",
        "discovery",
        "directory_enumeration",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Recursive content discovery.",
        executable="feroxbuster",
    ),
    _manifest(
        "gobuster",
        "discovery",
        "directory_enumeration",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Directory, DNS, and virtual-host discovery.",
        executable="gobuster",
    ),
    _manifest(
        "katana",
        "discovery",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Web crawling and endpoint inventory.",
        executable="katana",
    ),
    _manifest(
        "sqlmap",
        "validation",
        "exploit_attempt",
        RiskLevel.L2,
        IntegrationState.CATALOGED,
        "Reviewed SQL injection validation profiles.",
        executable="sqlmap",
    ),
    _manifest(
        "dalfox",
        "validation",
        "exploit_attempt",
        RiskLevel.L2,
        IntegrationState.CATALOGED,
        "Reviewed XSS parameter validation.",
        executable="dalfox",
    ),
    _manifest(
        "testssl",
        "scanner",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "TLS protocol, cipher, and certificate assessment.",
        executable="testssl.sh",
    ),
    _manifest(
        "zaproxy",
        "scanner",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "OWASP ZAP spidering and bounded active scan profiles.",
        executable="zap.sh",
    ),
    _manifest(
        "wapiti",
        "scanner",
        "active_api_probe",
        RiskLevel.L1,
        IntegrationState.CATALOGED,
        "Black-box Web vulnerability scanning.",
        executable="wapiti",
    ),
    _manifest(
        "whatweb",
        "recon",
        "passive_fingerprint",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Web technology fingerprinting.",
        executable="whatweb",
    ),
    _manifest(
        "wafw00f",
        "recon",
        "passive_fingerprint",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Web application firewall fingerprinting.",
        executable="wafw00f",
    ),
    _manifest(
        "subfinder",
        "recon",
        "passive_discovery",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Passive subdomain discovery.",
        executable="subfinder",
    ),
    _manifest(
        "amass",
        "recon",
        "passive_discovery",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Attack-surface and DNS mapping.",
        executable="amass",
    ),
    _manifest(
        "semgrep",
        "code",
        "passive_fingerprint",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Static source-code security analysis.",
        executable="semgrep",
    ),
    _manifest(
        "trivy",
        "code",
        "passive_fingerprint",
        RiskLevel.L0,
        IntegrationState.CATALOGED,
        "Dependency, image, filesystem, and configuration scanning.",
        executable="trivy",
    ),
)
_BY_NAME = {item.name: item for item in _TOOLS}


def get_tool(name: str) -> ToolManifest | None:
    """Return one canonical manifest without claiming local availability."""
    return _BY_NAME.get(name.strip().lower())


def list_tools(
    executable_resolver: Callable[[str], str | None] = shutil.which,
) -> tuple[ToolManifest, ...]:
    """List tools and resolve executable presence without running any program."""
    return tuple(
        manifest.model_copy(
            update={
                "installed": (
                    executable_resolver(manifest.executable) is not None
                    if manifest.executable is not None
                    else None
                )
            }
        )
        for manifest in _TOOLS
    )
