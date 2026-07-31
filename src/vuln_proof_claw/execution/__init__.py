"""Isolated worker protocol and lifecycle management."""

from vuln_proof_claw.execution.manager import WorkerManager
from vuln_proof_claw.execution.protocol import WorkerRequest, WorkerResponse

__all__ = ["WorkerManager", "WorkerRequest", "WorkerResponse"]
