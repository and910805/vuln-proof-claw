"""Stable domain enumerations."""

from enum import StrEnum


class RiskLevel(StrEnum):
    """Risk assigned before a target-facing action may execute."""

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"

    @property
    def requires_approval(self) -> bool:
        """Return whether the default policy requires explicit approval."""
        return self in {RiskLevel.L2, RiskLevel.L3, RiskLevel.L4}


class ActionState(StrEnum):
    """Lifecycle states for a proposed target-facing action."""

    PROPOSED = "proposed"
    POLICY_CHECK = "policy_check"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    WORKER_LOST = "worker_lost"


class WorkerState(StrEnum):
    """Durable control-plane state for one disposable Worker."""

    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"

    @property
    def terminal(self) -> bool:
        return self in {
            WorkerState.COMPLETED,
            WorkerState.FAILED,
            WorkerState.TIMED_OUT,
            WorkerState.CANCELLED,
            WorkerState.LOST,
        }


class FindingStatus(StrEnum):
    """Verification lifecycle for a potential finding."""

    CANDIDATE = "candidate"
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    REJECTED = "rejected"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class FindingSeverity(StrEnum):
    """User-facing impact rating for a finding."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(StrEnum):
    """Strength of the evidence supporting a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ArtifactKind(StrEnum):
    """Supported artifact categories."""

    SCREENSHOT = "screenshot"
    HTTP_ARCHIVE = "http_archive"
    PROOF_OF_CONCEPT = "proof_of_concept"
    DOWNLOAD = "download"
    REPORT = "report"
    OTHER = "other"


class ReportFormat(StrEnum):
    """Stable formats for immutable engagement report snapshots."""

    JSON = "json"
    MARKDOWN = "markdown"
