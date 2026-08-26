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
    BASELINE = "baseline"
    NEGATIVE_CONTROL = "negative_control"
    DOWNLOAD = "download"
    REPORT = "report"
    OTHER = "other"

    @property
    def is_control(self) -> bool:
        """Return whether this artifact acts as a comparison for a payload result."""
        return self in {ArtifactKind.BASELINE, ArtifactKind.NEGATIVE_CONTROL}


class ReportFormat(StrEnum):
    """Stable formats for immutable engagement report snapshots."""

    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class TaskState(StrEnum):
    """Progress of one planned unit of work, so a run can be resumed."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"

    @property
    def terminal(self) -> bool:
        """Return whether no further work will be done on this task."""
        return self in {TaskState.COMPLETED, TaskState.ABANDONED}

    @property
    def resumable(self) -> bool:
        """Return whether a fresh worker may pick this task up again."""
        return self in {TaskState.PLANNED, TaskState.RUNNING, TaskState.FAILED}


class VerificationMethod(StrEnum):
    """How a finding was established."""

    OBSERVED = "observed"
    DIFFERENTIAL = "differential"


class EffortLevel(StrEnum):
    """Reasoning effort requested for the agent driving an action."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"


class UsageKind(StrEnum):
    """Countable units that must never be conflated in a report."""

    LLM_CALL = "llm_call"
    TOOL_INVOCATION = "tool_invocation"
    TARGET_COMMAND = "target_command"
