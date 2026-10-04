"""The persistent mission controller.

The controller owns the autonomous loop. It observes, detects change, ranks leads,
asks the planner for a step, and submits that step to the policy engine. It never
executes anything the policy engine did not allow, and it holds no authoritative state
in memory: a crashed or rebooted process resumes from PostgreSQL alone.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from vuln_proof_claw.agent.budget import BudgetGate
from vuln_proof_claw.agent.candidates import (
    promote_candidate,
    record_endpoints,
    record_verdicts,
)
from vuln_proof_claw.agent.differential import OracleVerdict
from vuln_proof_claw.agent.endpoints import classify_endpoint
from vuln_proof_claw.agent.leads import (
    begin_attempt,
    evaluate_eligibility,
    mark_stale,
    rank_lead,
    reawaken,
    record_blocked,
    record_failure,
    record_rejected,
)
from vuln_proof_claw.agent.memory import ResearchMemory
from vuln_proof_claw.agent.planner import Planner, ResearchPlan, validate_plan
from vuln_proof_claw.agent.recon import ReconResult
from vuln_proof_claw.agent.scheduler import (
    RecurringTask,
    evaluate_task,
    is_stale,
    next_cycle_at,
)
from vuln_proof_claw.agent.surface import SurfaceTracker
from vuln_proof_claw.agent.sweep import EndpointSpec, ProbeOutcome, SweepPlan, plan_sweep
from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.autonomous import (
    AgentCycle,
    ChangeEvent,
    Lead,
    Mission,
    MissionRun,
)
from vuln_proof_claw.domain.enums import (
    ActionState,
    CycleState,
    LeadStatus,
    MissionRunState,
    MissionState,
)
from vuln_proof_claw.domain.identifiers import EngagementId, LeadId, MissionId
from vuln_proof_claw.domain.models import Action, Flow, Task
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.persistence.autonomous_repositories import (
    AgentCycleRepository,
    AssetRepository,
    EndpointRepository,
    LeadRepository,
    MissionRepository,
    MissionRunRepository,
)
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    AuditEventRepository,
    EngagementRepository,
    FlowRepository,
    ScopeRepository,
    Stored,
    TaskRepository,
)
from vuln_proof_claw.policy.decision import (
    DecisionKind,
    PolicyConfig,
    PolicyDecision,
    decide_action,
)
from vuln_proof_claw.policy.scope import normalize_target

_LOGGER = logging.getLogger(__name__)

DEFAULT_WATCHDOG_SECONDS = 900
_LEAD_SELECTION_LIMIT = 50
_SCHEDULABLE_STATUSES = (LeadStatus.NEW, LeadStatus.QUEUED, LeadStatus.WAITING)
_ENDPOINT_SELECTION_LIMIT = 500
_SWEEP_COMPLETED_EVENT = "agent.sweep_completed"


class MissionControllerError(Exception):
    """Raised when the controller cannot operate on the requested mission."""


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Outcome of performing one allowed action."""

    succeeded: bool
    reason: str
    evidence_ids: tuple[str, ...] = ()


@runtime_checkable
class Reconnaissance(Protocol):
    """Recover a target's API inventory.

    Implementations fetch through the scope-enforcing transport, so the controller does
    not need to know how a target exposes its surface.
    """

    def discover(self, *, at: datetime) -> ReconResult:
        """Return what one reconnaissance pass recovered."""
        ...


@runtime_checkable
class Prober(Protocol):
    """Probe a planned set of endpoints and judge what came back.

    Implementations receive only endpoints the controller has already cleared against
    the endpoint classifier and the mission's request budget. They must not widen the
    plan, and they must return verdicts rather than conclusions: a triggered rule is an
    observation, and promotion to a finding happens elsewhere.
    """

    def probe(self, endpoints: Sequence[EndpointSpec], *, at: datetime) -> ProbeOutcome:
        """Send the planned probes and return what the oracles concluded."""
        ...


@runtime_checkable
class ActionExecutor(Protocol):
    """Perform an action that the policy engine has already allowed.

    Implementations receive only actions carrying an ``ALLOW`` decision. They must not
    re-interpret the plan or widen the target.
    """

    def execute(self, action: Action, *, decision: PolicyDecision) -> ExecutionResult:
        """Execute one authorized action and report its outcome."""
        ...


@dataclass(frozen=True, slots=True)
class LeadOutcome:
    """What the controller did about one lead in a cycle."""

    lead_id: str
    disposition: str
    reason: str


@dataclass(frozen=True, slots=True)
class ReconSummary:
    """What reconnaissance contributed to a cycle."""

    endpoints_recorded: int = 0
    endpoints_held_back: int = 0
    candidates_created: int = 0
    leads_created: int = 0
    skipped: str | None = None


@dataclass(frozen=True, slots=True)
class SweepSummary:
    """What probing contributed to a cycle."""

    endpoints_probed: int = 0
    endpoints_withheld: int = 0
    requests_sent: int = 0
    verdicts_triggered: int = 0
    candidates_created: int = 0
    leads_created: int = 0
    skipped: str | None = None


@dataclass(frozen=True, slots=True)
class CycleReport:
    """A summary of one completed cycle.

    ``run`` carries the mission run as it stands after the cycle. Callers must use it
    for the next cycle or heartbeat: the cycle advances the run's version, so a handle
    held from before the cycle is already stale.
    """

    cycle: AgentCycle
    run: Stored[MissionRun]
    outcomes: tuple[LeadOutcome, ...]
    changes_detected: int
    next_cycle_at: datetime
    recon: ReconSummary = field(default_factory=ReconSummary)
    sweep: SweepSummary = field(default_factory=SweepSummary)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class MissionController:
    """Drive one autonomous mission across cycles, crashes, and restarts."""

    def __init__(  # noqa: PLR0913 - explicit collaborators keep the loop testable
        self,
        session: Session,
        mission_id: MissionId,
        *,
        planner: Planner,
        executor: ActionExecutor,
        actor: str = "agent:controller",
        clock: Callable[[], datetime] = _utc_now,
        reconnaissance: Reconnaissance | None = None,
        prober: Prober | None = None,
        probe_mutating: bool = False,
    ) -> None:
        self._session = session
        self._mission_id = mission_id
        self._planner = planner
        self._executor = executor
        self._reconnaissance = reconnaissance
        self._prober = prober
        self._probe_mutating = probe_mutating
        self._actor = actor
        self._clock = clock
        self._missions = MissionRepository(session)
        self._runs = MissionRunRepository(session)
        self._cycles = AgentCycleRepository(session)
        self._leads = LeadRepository(session)
        self._engagements = EngagementRepository(session)
        self._scopes = ScopeRepository(session)
        self._flows = FlowRepository(session)
        self._tasks = TaskRepository(session)
        self._actions = ActionRepository(session)

    # -- mission run lifecycle -------------------------------------------------

    def recover(self, *, watchdog_seconds: int = DEFAULT_WATCHDOG_SECONDS) -> tuple[str, ...]:
        """Reconcile state left behind by a crashed or killed controller.

        Runs whose heartbeat expired are marked interrupted, and any lead stuck in
        investigation is returned to the queue with its attempt already counted, so a
        restart loop cannot drive unbounded retries against a target.
        """
        now = self._now()
        recovered: list[str] = []
        for stored_run in self._runs.list_running():
            run = stored_run.entity
            if run.mission_id != self._mission_id:
                continue
            if not run.is_stale(at=now, timeout_seconds=watchdog_seconds):
                continue
            self._runs.save(
                replace(
                    run,
                    state=MissionRunState.INTERRUPTED,
                    error_code="watchdog_heartbeat_expired",
                    ended_at=now,
                ),
                expected_version=stored_run.version,
            )
            recovered.append(run.id)
            self._audit("mission.run_interrupted", {"mission_run_id": run.id}, at=now)

        for stored_lead in self._leads.list_by_status(
            self._mission_id, (LeadStatus.INVESTIGATING,), limit=_LEAD_SELECTION_LIMIT
        ):
            lead = stored_lead.entity
            self._leads.save(
                replace(
                    lead,
                    status=LeadStatus.QUEUED,
                    last_reasoning_summary="controller restarted during investigation",
                    updated_at=now,
                ),
                expected_version=stored_lead.version,
            )
        self._session.commit()
        return tuple(recovered)

    def start_run(self) -> Stored[MissionRun]:
        """Begin a new execution span for the mission."""
        stored_mission = self._require_mission()
        mission = stored_mission.entity
        now = self._now()
        if not mission.permits_cycle(at=now):
            raise MissionControllerError(self._blocked_reason(mission, at=now))

        previous = self._latest_cycle_index()
        run = MissionRun(
            engagement_id=mission.engagement_id,
            mission_id=mission.id,
            state=MissionRunState.RUNNING,
            cycle_index=previous,
            started_at=now,
            heartbeat_at=now,
        )
        self._runs.add(run)
        self._audit("mission.run_started", {"mission_run_id": run.id}, at=now)
        self._session.commit()
        stored = self._runs.get(run.id)
        if stored is None:  # pragma: no cover - the row was just written
            raise MissionControllerError("mission_run_not_persisted")
        return stored

    def heartbeat(self, stored_run: Stored[MissionRun]) -> Stored[MissionRun]:
        """Refresh the run's liveness marker so the watchdog leaves it alone."""
        now = self._now()
        updated = self._runs.save(
            replace(stored_run.entity, heartbeat_at=now),
            expected_version=stored_run.version,
        )
        self._session.commit()
        return updated

    def finish_run(
        self,
        stored_run: Stored[MissionRun],
        *,
        state: MissionRunState = MissionRunState.COMPLETED,
        error_code: str | None = None,
    ) -> Stored[MissionRun]:
        """Close an execution span."""
        now = self._now()
        updated = self._runs.save(
            replace(stored_run.entity, state=state, error_code=error_code, ended_at=now),
            expected_version=stored_run.version,
        )
        self._audit(
            "mission.run_finished",
            {"mission_run_id": stored_run.entity.id, "state": state.value},
            at=now,
        )
        self._session.commit()
        return updated

    # -- the cycle -------------------------------------------------------------

    def run_cycle(self, stored_run: Stored[MissionRun]) -> CycleReport:
        """Execute one observe, plan, act, and verify iteration."""
        stored_mission = self._require_mission()
        mission = stored_mission.entity
        now = self._now()
        if not mission.permits_cycle(at=now):
            raise MissionControllerError(self._blocked_reason(mission, at=now))

        run = stored_run.entity
        cycle = AgentCycle(
            engagement_id=mission.engagement_id,
            mission_run_id=run.id,
            index=run.cycle_index,
            state=CycleState.RUNNING,
            started_at=now,
        )
        self._cycles.add(cycle)
        self._session.commit()

        recon = self._reconnoitre(mission, at=now)
        sweep = self._probe_surface(mission, at=now)
        capture = SurfaceTracker(self._session, mission.engagement_id).capture(at=now)
        self._reawaken_changed_leads(capture.changes, at=now)
        self._expire_stale_leads(mission, at=now)

        outcomes = self._work_leads(mission, at=now)

        completed = replace(
            cycle,
            state=CycleState.COMPLETED,
            leads_considered=len(outcomes),
            actions_proposed=sum(1 for item in outcomes if item.disposition != "skipped"),
            actions_executed=sum(1 for item in outcomes if item.disposition == "executed"),
            ended_at=self._now(),
        )
        stored_cycle = self._cycles.get(cycle.id)
        if stored_cycle is None:  # pragma: no cover - the row was just written
            raise MissionControllerError("agent_cycle_not_persisted")
        self._cycles.save(completed, expected_version=stored_cycle.version)
        advanced = self._runs.save(
            replace(run, cycle_index=run.cycle_index + 1, heartbeat_at=self._now()),
            expected_version=stored_run.version,
        )
        self._session.commit()

        return CycleReport(
            cycle=completed,
            run=advanced,
            outcomes=outcomes,
            changes_detected=len(capture.changes),
            next_cycle_at=next_cycle_at(mission.cadence, now=self._now()),
            recon=recon,
            sweep=sweep,
        )

    # -- internals -------------------------------------------------------------

    def _reconnoitre(self, mission: Mission, *, at: datetime) -> ReconSummary:
        """Recover the target's API surface and turn new observations into leads.

        Runs on the mission's inventory cadence rather than every cycle: a redeployed
        bundle is the signal worth acting on, and refetching it every few minutes is
        the kind of repetition the activity rules forbid.

        A reconnaissance failure never fails the cycle. Losing one pass costs a delay;
        aborting the cycle would also abandon the leads already waiting to be worked.
        """
        if self._reconnaissance is None:
            return ReconSummary(skipped="no_reconnaissance_configured")

        decision = evaluate_task(
            RecurringTask.HTTP_INVENTORY,
            mission.cadence,
            last_run_at=self._last_recon_at(mission.engagement_id),
            now=at,
        )
        if not decision.due:
            return ReconSummary(skipped=decision.reason)

        try:
            result = self._reconnaissance.discover(at=at)
        except Exception as error:  # noqa: BLE001 - recon must not fail the cycle
            _LOGGER.warning("reconnaissance failed: %s", error)
            self._audit("agent.recon_failed", {"error": str(error)[:200]}, at=at)
            self._session.commit()
            return ReconSummary(skipped="reconnaissance_failed")

        if not result.classifications:
            return ReconSummary(skipped="no_endpoints_recovered")

        stored, held = record_endpoints(
            self._session,
            mission.engagement_id,
            result.base_url,
            result.classifications,
            at=at,
        )
        self._audit(
            "agent.recon_completed",
            {
                "endpoints": stored,
                "held_back": held,
                "surface_digest": result.surface_digest,
            },
            at=at,
        )
        self._session.commit()
        return ReconSummary(endpoints_recorded=stored, endpoints_held_back=held)

    def _probe_surface(self, mission: Mission, *, at: datetime) -> SweepSummary:
        """Probe the recovered surface and turn what the oracles say into leads.

        This is the step that makes the loop autonomous rather than merely scheduled:
        without it the agent knows an endpoint exists but has never asked it anything.

        Three limits apply before a single request is sent. The classifier decides what
        may be called at all, the budget decides how many, and the cadence decides how
        often. A sweep is bounded work on an interval, not a scan.

        Like reconnaissance, a failure here is contained. The sweep talks to a live
        target over a network that may be gone; losing a pass must not cost the cycle.
        """
        prepared = self._prepare_sweep(mission, at=at)
        if isinstance(prepared, str):
            return SweepSummary(skipped=prepared)
        plan, host, gate = prepared
        if not plan.endpoints:
            return SweepSummary(
                endpoints_withheld=len(plan.withheld), skipped="nothing_safe_to_probe"
            )
        if self._prober is None:  # pragma: no cover - _prepare_sweep already refused
            return SweepSummary(skipped="no_prober_configured")

        try:
            outcome = self._prober.probe(plan.endpoints, at=at)
        except Exception as error:  # noqa: BLE001 - a sweep must not fail the cycle
            _LOGGER.warning("sweep failed: %s", error)
            self._audit("agent.sweep_failed", {"error": str(error)[:200]}, at=at)
            self._session.commit()
            return SweepSummary(skipped="sweep_failed")

        for _ in range(outcome.requests_sent):
            gate.record_request(host=host, at=at)
        self._audit(
            _SWEEP_COMPLETED_EVENT,
            {
                "probed": len(plan.endpoints),
                "withheld": len(plan.withheld),
                "requests_sent": outcome.requests_sent,
                "stopped_early": outcome.stopped_early or "",
            },
            at=at,
        )
        self._session.commit()

        recorded = self.record_observations(outcome.verdicts, at=at)
        return SweepSummary(
            endpoints_probed=len(plan.endpoints),
            endpoints_withheld=len(plan.withheld),
            requests_sent=outcome.requests_sent,
            verdicts_triggered=sum(1 for item in outcome.verdicts if item.triggered),
            candidates_created=recorded.candidates_created,
            leads_created=recorded.leads_created,
            skipped=outcome.stopped_early,
        )

    def _prepare_sweep(
        self, mission: Mission, *, at: datetime
    ) -> tuple[SweepPlan, str, BudgetGate] | str:
        """Decide whether to sweep and what the sweep may touch.

        Returns the reason for not sweeping, or the plan together with the host the
        requests will be charged against and the gate that will charge them.
        """
        if self._prober is None:
            return "no_prober_configured"

        decision = evaluate_task(
            RecurringTask.DEEP_RECON,
            mission.cadence,
            last_run_at=AuditEventRepository(self._session).last_occurrence(
                mission.engagement_id, _SWEEP_COMPLETED_EVENT
            ),
            now=at,
        )
        if not decision.due:
            return decision.reason

        endpoints = EndpointRepository(self._session).list_for_engagement(
            mission.engagement_id, limit=_ENDPOINT_SELECTION_LIMIT
        )
        if not endpoints:
            return "no_endpoints_known"

        host = normalize_target(self._base_of(mission)).host
        gate = BudgetGate(self._session, mission)
        headroom = gate.remaining_requests(host=host, at=at)
        if headroom <= 0:
            return "request_budget_exhausted"

        plan = plan_sweep(
            [
                classify_endpoint(stored.entity.method, stored.entity.path)
                for stored in endpoints
            ],
            limit=headroom,
            include_mutating=self._probe_mutating,
        )
        return (plan, host, gate)

    def _base_of(self, mission: Mission) -> str:
        """Return a target the budget can be accounted against.

        Endpoints are stored as paths; the host comes from the asset they belong to.
        """
        endpoints = EndpointRepository(self._session).list_for_engagement(
            mission.engagement_id, limit=1
        )
        asset = (
            AssetRepository(self._session).get(endpoints[0].entity.asset_id)
            if endpoints
            else None
        )
        if asset is None:  # pragma: no cover - guarded by the caller's empty check
            raise MissionControllerError("endpoint_asset_unavailable")
        return f"https://{asset.entity.identifier}/"

    def record_observations(
        self,
        verdicts: Sequence[OracleVerdict],
        *,
        at: datetime | None = None,
    ) -> ReconSummary:
        """Turn oracle verdicts into candidates and schedulable leads.

        Separate from the cycle so a sweep can be driven independently and still land
        its conclusions in the same knowledge base.
        """
        mission = self._require_mission().entity
        moment = at or self._now()
        recorded = record_verdicts(
            self._session, mission.engagement_id, verdicts, at=moment
        )
        by_target = {
            (verdict.rule.value, verdict.target): verdict
            for verdict in verdicts
            if verdict.triggered
        }
        leads = 0
        for candidate in recorded.created:
            verdict = by_target.get((candidate.severity_hint or "", candidate.target))
            if verdict is None:  # pragma: no cover - keys are built from the same list
                continue
            if promote_candidate(
                self._session,
                candidate,
                mission_id=mission.id,
                verdict=verdict,
                at=moment,
            ):
                leads += 1
        self._session.commit()
        return ReconSummary(candidates_created=recorded.total, leads_created=leads)

    def _last_recon_at(self, engagement_id: EngagementId) -> datetime | None:
        """Return when reconnaissance last stored an endpoint, if ever."""
        endpoints = EndpointRepository(self._session).list_for_engagement(
            engagement_id, limit=1
        )
        return endpoints[0].entity.last_seen_at if endpoints else None

    def _work_leads(self, mission: Mission, *, at: datetime) -> tuple[LeadOutcome, ...]:
        memory = ResearchMemory(self._session, mission.engagement_id)
        gate = BudgetGate(self._session, mission)
        candidates = self._leads.list_due(
            mission.id, _SCHEDULABLE_STATUSES, at=at, limit=_LEAD_SELECTION_LIMIT
        )
        ordered = sorted(
            candidates,
            key=lambda stored: rank_lead(stored.entity, now=at),
            reverse=True,
        )

        outcomes: list[LeadOutcome] = []
        executed = 0
        for stored in ordered:
            if executed >= mission.budget.maximum_concurrent_actions:
                break
            outcome = self._work_one_lead(stored, mission=mission, memory=memory, gate=gate, at=at)
            outcomes.append(outcome)
            if outcome.disposition == "executed":
                executed += 1
            if outcome.reason.endswith("_budget_exhausted") or outcome.reason.endswith(
                "_ceiling_reached"
            ):
                break
        return tuple(outcomes)

    def _work_one_lead(
        self,
        stored: Stored[Lead],
        *,
        mission: Mission,
        memory: ResearchMemory,
        gate: BudgetGate,
        at: datetime,
    ) -> LeadOutcome:
        lead = stored.entity
        eligibility = evaluate_eligibility(
            lead,
            now=at,
            budget=mission.budget,
            has_new_evidence=memory.has_new_evidence_since(lead),
        )
        if not eligibility:
            return LeadOutcome(lead.id, "skipped", eligibility.reason)

        plan = self._planner.plan(lead, mission=mission)
        if plan is None:
            return LeadOutcome(lead.id, "skipped", "no_plan_available")

        rejection = validate_plan(plan, mission=mission)
        if rejection is not None:
            self._save_lead(record_rejected(lead, reason=rejection.reason, now=at), stored.version)
            self._audit(
                "agent.plan_rejected",
                {"lead_id": lead.id, "reason": rejection.reason},
                at=at,
            )
            self._session.commit()
            return LeadOutcome(lead.id, "rejected", rejection.reason)

        host = normalize_target(plan.proposed_action.target).host
        budget_decision = gate.permits_request(host=host, at=at)
        if not budget_decision:
            return LeadOutcome(lead.id, "skipped", budget_decision.reason)

        return self._execute_plan(stored, plan, mission=mission, gate=gate, at=at)

    def _execute_plan(
        self,
        stored: Stored[Lead],
        plan: ResearchPlan,
        *,
        mission: Mission,
        gate: BudgetGate,
        at: datetime,
    ) -> LeadOutcome:
        lead = stored.entity
        attempting = begin_attempt(lead, now=at)
        self._save_lead(attempting, stored.version)
        self._session.commit()

        action = self._create_action(plan, mission=mission, lead=attempting, at=at)
        decision = self._decide(action, mission=mission, at=at)
        self._audit(
            "policy.decision",
            {
                "action_id": action.id,
                "lead_id": lead.id,
                "kind": decision.kind.value,
                "reason": decision.reason,
                "risk_level": decision.risk_level.value,
            },
            at=at,
        )

        current = self._reload_lead(lead.id)
        if decision.kind is DecisionKind.DENY:
            self._transition_action(action, ActionState.DENIED, at=at)
            self._save_lead(
                record_rejected(current.entity, reason=decision.reason, now=at),
                current.version,
            )
            self._session.commit()
            return LeadOutcome(lead.id, "rejected", decision.reason)

        if decision.kind is DecisionKind.APPROVAL_REQUIRED:
            self._transition_action(action, ActionState.PENDING_APPROVAL, at=at)
            self._save_lead(
                record_blocked(current.entity, reason=decision.reason, now=at),
                current.version,
            )
            self._session.commit()
            return LeadOutcome(lead.id, "needs_approval", decision.reason)

        queued = self._transition_action(action, ActionState.QUEUED, at=at)
        gate.record_request(host=decision.target.host, at=at)
        self._session.commit()

        result = self._executor.execute(queued, decision=decision)
        final = self._reload_lead(lead.id)
        if not result.succeeded:
            self._save_lead(
                record_failure(
                    final.entity, reason=result.reason, cadence=mission.cadence, now=self._now()
                ),
                final.version,
            )
            self._session.commit()
            return LeadOutcome(lead.id, "failed", result.reason)

        completed_at = self._now()
        self._save_lead(
            replace(
                final.entity,
                status=LeadStatus.WAITING,
                last_reasoning_summary=result.reason,
                # A successful attempt still earns a cooldown. Without one the lead is
                # immediately re-selected on the next cycle and spends the whole
                # request budget re-reading the same target.
                next_attempt_at=completed_at
                + timedelta(seconds=mission.cadence.http_inventory_seconds),
                updated_at=completed_at,
            ),
            final.version,
        )
        self._session.commit()
        return LeadOutcome(lead.id, "executed", result.reason)

    def _create_action(
        self,
        plan: ResearchPlan,
        *,
        mission: Mission,
        lead: Lead,
        at: datetime,
    ) -> Action:
        flow = self._ensure_flow(mission, at=at)
        task = Task(flow_id=flow.id, title=plan.objective[:500], created_at=at)
        self._tasks.add(task)
        action = Action(
            engagement_id=mission.engagement_id,
            task_id=task.id,
            action_type=plan.proposed_action.action_type,
            normalized_target=plan.proposed_action.target,
            parameter_digest=http_parameter_digest(
                method="GET",
                target=plan.proposed_action.target,
                headers=(),
                query=plan.proposed_action.query,
            ),
            query=plan.proposed_action.query,
            risk_level=plan.risk_level,
            idempotency_key=f"mission:{mission.id}:lead:{lead.id}:attempt:{lead.attempt_count}",
            state=ActionState.PROPOSED,
            created_at=at,
        )
        self._actions.add(action)
        self._session.flush()
        return action

    def _ensure_flow(self, mission: Mission, *, at: datetime) -> Flow:
        objective = f"autonomous mission: {mission.name}"
        for stored in self._flows.list_for_engagement(mission.engagement_id, limit=100):
            if stored.entity.objective == objective:
                return stored.entity
        flow = Flow(engagement_id=mission.engagement_id, objective=objective, created_at=at)
        self._flows.add(flow)
        return flow

    def _decide(self, action: Action, *, mission: Mission, at: datetime) -> PolicyDecision:
        stored_engagement = self._engagements.get(mission.engagement_id)
        scope = self._scopes.get(mission.engagement_id)
        if stored_engagement is None or scope is None:
            raise MissionControllerError("engagement_scope_unavailable")
        engagement = stored_engagement.entity
        return decide_action(
            action,
            scope=scope,
            config=PolicyConfig(
                maximum_risk=engagement.maximum_risk,
                auto_execute_l1=engagement.auto_execute_l1,
                destructive_actions_enabled=engagement.destructive_actions_enabled,
            ),
            at=at,
        )

    def _transition_action(self, action: Action, state: ActionState, *, at: datetime) -> Action:
        stored = self._actions.get(action.id)
        if stored is None:  # pragma: no cover - the row was just written
            raise MissionControllerError("action_not_persisted")
        started = at if state is ActionState.QUEUED else action.started_at
        updated = replace(action, state=state, started_at=started)
        self._actions.save(updated, expected_version=stored.version)
        return updated

    def _reawaken_changed_leads(self, changes: Sequence[ChangeEvent], *, at: datetime) -> None:
        if not changes:
            return
        for stored in self._leads.list_by_status(
            self._mission_id,
            (LeadStatus.STALE, LeadStatus.REJECTED),
            limit=_LEAD_SELECTION_LIMIT,
        ):
            self._save_lead(
                reawaken(stored.entity, reason="attack_surface_changed", now=at),
                stored.version,
            )
        self._session.commit()

    def _expire_stale_leads(self, mission: Mission, *, at: datetime) -> None:
        for stored in self._leads.list_by_status(
            mission.id, _SCHEDULABLE_STATUSES, limit=_LEAD_SELECTION_LIMIT
        ):
            if is_stale(stored.entity, mission.cadence, now=at):
                self._save_lead(mark_stale(stored.entity, now=at), stored.version)
        self._session.commit()

    def _save_lead(self, lead: Lead, expected_version: int) -> None:
        self._leads.save(lead, expected_version=expected_version)

    def _reload_lead(self, lead_id: str) -> Stored[Lead]:
        stored = self._leads.get(LeadId(lead_id))
        if stored is None:  # pragma: no cover - the row was just written
            raise MissionControllerError("lead_not_persisted")
        return stored

    def _require_mission(self) -> Stored[Mission]:
        stored = self._missions.get(self._mission_id)
        if stored is None:
            raise MissionControllerError("mission_not_found")
        return stored

    def _latest_cycle_index(self) -> int:
        highest = 0
        for stored in self._runs.list_running(limit=_LEAD_SELECTION_LIMIT):
            if stored.entity.mission_id == self._mission_id:
                highest = max(highest, stored.entity.cycle_index)
        return highest

    @staticmethod
    def _blocked_reason(mission: Mission, *, at: datetime) -> str:
        if mission.kill_switch_engaged:
            return "kill_switch_engaged"
        if mission.expires_at is not None and at >= mission.expires_at:
            return "mission_expired"
        if mission.state is MissionState.PAUSED:
            return "mission_paused"
        return f"mission_not_schedulable_{mission.state.value}"

    def _audit(self, event_type: str, payload: dict[str, object], *, at: datetime) -> None:
        record_audit_event(
            self._session,
            self._require_mission().entity.engagement_id,
            event_type,
            self._actor,
            {**payload, "mission_id": self._mission_id},
            at=at,
        )

    def _now(self) -> datetime:
        return self._clock()


__all__ = [
    "DEFAULT_WATCHDOG_SECONDS",
    "ActionExecutor",
    "CycleReport",
    "ExecutionResult",
    "LeadOutcome",
    "MissionController",
    "MissionControllerError",
    "ProbeOutcome",
    "Prober",
    "ReconSummary",
    "Reconnaissance",
    "SweepSummary",
]
