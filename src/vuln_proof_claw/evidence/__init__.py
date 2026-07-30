"""Tamper-evident evidence primitives."""

from vuln_proof_claw.evidence.hash_chain import append_to_chain, verify_chain
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord
from vuln_proof_claw.evidence.store import InMemoryEvidenceStore

__all__ = [
    "EvidenceMetadata",
    "EvidenceRecord",
    "InMemoryEvidenceStore",
    "append_to_chain",
    "verify_chain",
]
