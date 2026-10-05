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


class MissionState(StrEnum):
    """Lifecycle of a long-running autonomous research campaign."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXPIRED = "expired"
    STOPPED = "stopped"

    @property
    def terminal(self) -> bool:
        """Return whether no further cycles may run for this mission."""
        return self in {MissionState.COMPLETED, MissionState.EXPIRED, MissionState.STOPPED}

    @property
    def schedulable(self) -> bool:
        """Return whether the controller may begin a new cycle."""
        return self is MissionState.RUNNING


class MissionRunState(StrEnum):
    """Durable state for one continuous mission execution span."""

    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {
            MissionRunState.INTERRUPTED,
            MissionRunState.COMPLETED,
            MissionRunState.FAILED,
        }


class CycleState(StrEnum):
    """State of a single observe/plan/act/verify iteration."""

    RUNNING = "running"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self is not CycleState.RUNNING


class LeadStatus(StrEnum):
    """Investigation lifecycle for a research hypothesis."""

    NEW = "new"
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    WAITING = "waiting"
    NEEDS_APPROVAL = "needs_approval"
    VERIFIED = "verified"
    REJECTED = "rejected"
    STALE = "stale"
    CLOSED = "closed"

    @property
    def terminal(self) -> bool:
        """Return whether the lead requires no further autonomous work."""
        return self in {LeadStatus.VERIFIED, LeadStatus.REJECTED, LeadStatus.CLOSED}

    @property
    def eligible_for_scheduling(self) -> bool:
        """Return whether the status permits the controller to select the lead."""
        return self in {LeadStatus.NEW, LeadStatus.QUEUED, LeadStatus.WAITING}

    @property
    def reawakenable(self) -> bool:
        """Return whether new evidence may return the lead to active investigation."""
        return self in {LeadStatus.STALE, LeadStatus.REJECTED, LeadStatus.WAITING}


class AssetKind(StrEnum):
    """Category of a discovered asset in the knowledge base."""

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    WEB_APPLICATION = "web_application"
    API = "api"


class ObservationKind(StrEnum):
    """Category of a raw recorded phenomenon."""

    HTTP_RESPONSE = "http_response"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    HTTP_HEADER = "http_header"
    API_SCHEMA = "api_schema"
    JAVASCRIPT = "javascript"
    TECHNOLOGY = "technology"
    ERROR_MESSAGE = "error_message"


class CandidateSource(StrEnum):
    """Origin of a candidate issue awaiting Planner triage."""

    SCANNER = "scanner"
    HEURISTIC = "heuristic"
    DIFFERENTIAL = "differential"
    SCHEMA_ANALYSIS = "schema_analysis"
    MANUAL = "manual"


class ChangeKind(StrEnum):
    """Typed attack-surface difference between two snapshots."""

    ASSET_ADDED = "asset_added"
    ASSET_REMOVED = "asset_removed"
    ENDPOINT_ADDED = "endpoint_added"
    ENDPOINT_REMOVED = "endpoint_removed"
    PARAMETER_ADDED = "parameter_added"
    TECHNOLOGY_CHANGED = "technology_changed"
    API_SCHEMA_CHANGED = "api_schema_changed"
    JAVASCRIPT_CHANGED = "javascript_changed"
    RESPONSE_CHANGED = "response_changed"
    AUTHENTICATION_CHANGED = "authentication_changed"


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
