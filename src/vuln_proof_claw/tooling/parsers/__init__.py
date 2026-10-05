"""Turn one tool's output into findings the control plane can govern.

A parser is the half of a tool integration that decides what the run *claimed*.
Building an argv only decides what ran. Everything a parser emits becomes a
``Finding`` that flows into scoring, the report and the disclosure bundle, so a
parser that reports inventory as vulnerability is the false-positive flood, not
a scanner that is too noisy.

Every parser here holds to the same three rules:

* **Inventory is not a finding.** A title, a status code, a technology list, a
  content length -- those describe the target. They are not claims about it.
* **A finding names its CWE and its basis.** Anything emitted carries a
  ``cwe_id`` and a ``verification_method``, because a claim a third party
  cannot key on or check is not worth shipping.
* **Nothing outside the approved target becomes a finding.** Output that names
  another host is dropped, not reported. A tool that wanders is a scope problem
  to surface, never a finding to mint.
"""

from __future__ import annotations

__all__ = [
    "NucleiParseResult",
    "SuppressedRecord",
    "Suppression",
    "parse_httpx_findings",
    "parse_nuclei_output",
]

from vuln_proof_claw.tooling.parsers.httpx import parse_httpx_findings
from vuln_proof_claw.tooling.parsers.nuclei import (
    NucleiParseResult,
    SuppressedRecord,
    Suppression,
    parse_nuclei_output,
)
