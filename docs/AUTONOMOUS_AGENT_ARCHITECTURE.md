# Autonomous Agent Architecture

This document specifies the migration of ProofClaw from a request-driven assessment
control plane into a **persistent, stateful, evidence-driven autonomous security
research agent** for explicitly authorized bug bounty engagements.

It is a migration plan, not a rewrite. Every existing security control is preserved
and reused; the autonomous layer is added *above* them and is structurally unable to
bypass them.

---

## 1. Non-negotiable invariants

These hold for every phase. A change that weakens one is a defect, not a trade-off.

1. **Evidence before claims.** A `Finding` is only ever produced by the Verifier from
   reproducible evidence. Scanners and heuristics produce `Candidate`s, never findings.
2. **No action outside authorized scope.** Every target-facing operation passes
   `policy.scope.evaluate_scope()`. Scope is default-deny, deny-before-allow.
3. **The agent cannot approve itself.** L2/L3 require a human approval record that is
   bound to the exact `(action_type, normalized_target, parameter_digest, risk_level)`.
4. **The agent cannot reclassify risk.** `policy.risk.classify_risk()` is a static table
   keyed by `action_type`; `decide_action()` denies on `risk_classification_mismatch`.
   An LLM proposing an action cannot choose its own risk level.
5. **L4 is permanently denied.** No configuration path enables destructive operations
   for autonomous execution.
6. **No evasion.** CAPTCHA solving, WAF bypass, and defeating bot detection are out of
   scope by design, not by omission. Encountering them is a *stop* signal.
7. **Every action is auditable.** `audit_events` records the decision, the actor, and
   the canonical payload for every control-plane transition.
8. **A failed hypothesis is not retried without new evidence.** Enforced
   deterministically by the Lead cooldown rules, not by LLM judgement.

---

## 2. What already exists (reused, not replaced)

The repository already implements most of the hard safety machinery. The autonomous
layer is a consumer of these, never a peer.

| Capability | Module | Status |
|---|---|---|
| Default-deny scope engine | `policy/scope.py` | Reused; extended with wildcard domains |
| Deterministic risk table L0–L4 | `policy/risk.py` | Reused as-is |
| Policy decision (scope+risk+approval) | `policy/decision.py:decide_action` | Reused as-is |
| One-shot bound approvals | `policy/approval.py`, `domain/models.py:Approval` | Reused as-is |
| Execution authorization chokepoint | `execution/authorization.py` | Reused as-is |
| Disposable worker lifecycle | `execution/lifecycle.py`, `execution/manager.py` | Reused |
| Container isolation (read-only, cap-drop ALL, internal network, non-root, pinned digest) | `execution/docker_runtime.py`, `engine/docker_backend.py` | Reused |
| DNS-pinned egress + SSRF guard | `execution/pinned_http.py` | Reused |
| Evidence hash chain | `evidence/hash_chain.py`, `evidence/persistence.py` | Reused |
| Planner/Operator/Verifier step machine | `automation/autonomy.py` | Reused as the cycle core |
| Tool registry + typed contracts | `tooling/registry.py`, `tooling/contracts.py` | Extended per phase |
| Audit events | `audit.py` | Reused |
| Passive discovery / OpenAPI parsing | `assessment/` | Reused by the recon cycle |

**Key structural fact:** `execution/authorization.py:authorize_queued_action()` re-runs
`decide_action()` immediately before execution, against the live database scope. The
autonomous controller therefore cannot execute an action by any path that skips policy,
even if its own in-memory state were corrupted or an LLM returned adversarial output.

---

## 3. Gap analysis

What the autonomous agent requires that does not exist today:

| Gap | Addressed in |
|---|---|
| No persistent loop; everything is request-driven | Phase 1 — Mission Controller |
| No hypothesis object between scanner output and Finding | Phase 1 — Lead |
| No asset/endpoint inventory or research memory | Phase 1 — Knowledge base |
| No cadence/scheduling or cooldown logic | Phase 1 — Scheduler |
| No rate limits, request budgets, or token budgets | Phase 1 — Budget ledger |
| No attack-surface snapshots or change detection | Phase 1 (core) / Phase 6 (full) |
| Wildcard bug bounty scope (`*.example.com`) unsupported | Phase 1 — Scope extension |
| No recon tool adapters (subfinder/httpx/katana/nuclei…) | Phase 2 |
| No ZAP / Burp integration | Phases 3–4 |
| No identity model or differential authorization testing | Phase 5 |
| No autonomous planner prompt/loop with LLM | Phase 7 |
| No agent-status dashboard | Phase 8 |
| No bug bounty draft report generator | Phase 9 |

---

## 4. Target object model

### 4.1 The evidence ladder

The central discipline of the system. Each arrow is a distinct, auditable promotion,
and only the last one may be performed by the Verifier.

```
Observation        raw recorded phenomenon (a response, a header, a DNS answer)
    |                  deterministic normalization
    v
Candidate          a scanner/heuristic thinks something may be wrong
    |                  Planner judges it worth investigating
    v
Lead               a testable hypothesis with confidence and a next action
    |                  Verifier independently reproduces and rules out benign causes
    v
Finding            reproducible, evidence-backed, scope-confirmed
```

`nuclei`, ZAP, and Burp results enter at **Candidate**. There is no code path from a
scanner result to a `Finding`. This is enforced in `agent/leads.py:promote_to_finding()`,
which requires a `VerificationOutcome` carrying evidence identifiers.

### 4.2 Mission objects

```
Project
  └── Engagement                  (existing: scope, risk ceiling, time bounds)
        └── Mission               autonomous research campaign config + state
              └── MissionRun      one continuous execution span (crash-recoverable)
                    └── AgentCycle    one observe→plan→act→verify iteration
                          └── AgentTask   a unit of work within the cycle
                                └── Action  (existing) the policy-gated operation
```

`Action` is unchanged — the autonomous layer produces the same `Action` rows the REST
API produces, and they flow through the same policy and execution path.

### 4.3 Lead

```
id, engagement_id, mission_id, asset_id
title, hypothesis, category
confidence (0..1), priority (0..100)
status: new|queued|investigating|waiting|needs_approval|verified|rejected|stale|closed
origin: tuple[str, ...]              provenance, e.g. ("openapi-analysis",)
evidence_ids, related_findings
attempt_count, failure_count
last_attempt_at, next_attempt_at
last_reasoning_summary, next_action, blocked_reason
created_at, updated_at
```

**Lead ≠ Finding.** A Lead carries a hypothesis and a plan; a Finding carries proof.

### 4.4 Knowledge base

Per-target persistent research memory, queried *before* every planning decision:

- `Asset` — hostname / IP / service, with first-seen and last-seen
- `Endpoint` — method + path + parameters, with auth requirement
- `Observation` — immutable recorded phenomena linked to evidence
- `AttackSurfaceSnapshot` — content digest of the surface at a point in time
- `ChangeEvent` — a typed diff between snapshots

The Planner must answer these before proposing an action, and the answers come from
deterministic SQL, not from an LLM's recollection:

1. What have we already tried against this asset/endpoint?
2. Which hypotheses already failed, and why?
3. Has new evidence arrived since the last attempt?
4. Has the attack surface changed?
5. Is a retry justified?

---

## 5. Control flow

### 5.1 The mission loop

```python
while mission.active and not kill_switch_engaged:
    cycle = begin_cycle(mission_run)

    observe_environment(cycle)          # refresh inventory, snapshot surface
    detect_changes(cycle)               # emit ChangeEvents, wake stale leads
    generate_or_update_leads(cycle)     # candidates -> leads
    leads = rank_eligible_leads(cycle)  # deterministic priority + cooldown filter

    for lead in leads:
        if not budget.permits(lead):
            break
        plan = planner.plan(lead)                 # structured JSON, no side effects
        decision = policy.evaluate(plan)          # decide_action()
        if decision.kind is ALLOW:
            result = operator.execute(plan)       # existing worker path
            verifier.evaluate(result)             # independent; may create Finding
        elif decision.kind is APPROVAL_REQUIRED:
            lead.block("needs_approval")
        else:
            lead.reject(decision.reason)
        memory.record(cycle, lead, result)

    schedule_next_cycle(mission_run)
```

The worker never decides the next step. The Planner proposes; the Policy Engine
decides; the Operator executes only what was allowed; the Verifier judges independently.

### 5.2 Crash and reboot recovery

`MissionRun` holds `state`, `heartbeat_at`, and `cycle_index`. On startup:

1. Any `MissionRun` in `RUNNING` whose heartbeat is older than the watchdog threshold
   is marked `INTERRUPTED`.
2. `execution/janitor.py:recover_runtime_after_restart()` reconciles orphaned workers
   (already implemented).
3. Leads left in `INVESTIGATING` are returned to `QUEUED` with their attempt counted —
   an interrupted attempt is a *used* attempt, so a crash loop cannot drive unbounded
   retries against a target.
4. A fresh `MissionRun` resumes from the persisted cycle index.

No in-memory state is authoritative. Everything needed to resume is in PostgreSQL.

### 5.3 Budgets and rate limits

A deterministic ledger enforced before any action is proposed:

- per-domain requests/minute
- per-mission requests/hour and requests/day
- total mission request budget
- LLM tokens per engagement/day/lead

Exceeding a limit pauses the relevant work and emits an audit event; it never silently
drops a lead. On HTTP 429 or observed WAF blocking, the controller backs off and lowers
the effective rate — it does not attempt to circumvent the control.

---

## 6. Risk policy mapping

Unchanged from `policy/risk.py`, restated here because autonomous execution depends on it:

| Level | Meaning | Default |
|---|---|---|
| L0 | Passive intelligence | AUTO |
| L1 | Low-impact authorized enumeration | AUTO (per-engagement `auto_execute_l1`) |
| L2 | State-changing / exploit-like verification | MANUAL APPROVAL |
| L3 | Post-exploitation | MANUAL APPROVAL |
| L4 | Destructive / persistence | **DENY, always** |

An engagement may *raise* the approval requirement but never lower L4. Any reduction of
a specific L2 behaviour requires explicit operator configuration and is never inferred
by the agent.

Autonomous missions run with an effective ceiling of **L1**. Reaching an L2 conclusion
produces a `needs_approval` Lead with a drafted plan for a human to review — never an
execution.

---

## 7. Phase plan

Each phase delivers code, migration, tests, and bilingual documentation.

| Phase | Scope | State |
|---|---|---|
| 1 | Mission Controller, Lead model, knowledge base, scheduler, budgets, wildcard scope | **Implemented** |
| 2 | Recon worker adapters (subfinder, dnsx, httpx, naabu, katana, gau, nuclei) | Planned |
| 3 | OWASP ZAP integration (passive, spider, AJAX spider, API import) | Planned |
| 4 | Burp Suite adapter (REST / DAST GraphQL) | Planned |
| 5 | Identity model + differential authorization testing | Planned |
| 6 | Full change detection and surface-diff driven re-investigation | Planned |
| 7 | LLM Planner/Verifier loop with structured output and token budgets | Planned |
| 8 | Agent observability dashboard | Planned |
| 9 | Bug bounty draft report generation | Planned |

### Phase 2+ integration rule

Every new scanner adapter follows the existing four-point registration, and lands at
Candidate, never Finding:

1. `tooling/registry.py` — a `_manifest(...)` entry whose `name` equals the contract `kind`
2. `tooling/contracts.py` — a typed `ToolParameters` subclass added to `ToolParameterUnion`
3. `policy/risk.py` — an `ACTION_RISK_LEVELS` row binding `action_type` to a risk level
4. `tooling/executor.py` — an argv builder branch

Scanner output is normalized to `Candidate` records by an adapter-specific normalizer.
`zap_active_scan` and any Burp active scan are L2 and therefore require approval.

---

## 8. Testing strategy

- **Deterministic units.** Scope, risk, budget, scheduler, lead eligibility, and ranking
  are pure functions with no I/O and are tested exhaustively, including adversarial input.
- **Policy bypass tests.** Explicit negative tests assert that a controller-produced
  action with a tampered risk level, widened scope, or forged approval is denied.
- **Crash recovery tests.** A mission run is interrupted mid-cycle and resumed; leads
  must not lose their attempt accounting.
- **Local-only integration targets.** Autonomous end-to-end tests run exclusively against
  a local intentionally-vulnerable application. CI never scans the public Internet; the
  scope engine's default-deny plus an explicit localhost-only scope enforces this.

---

## 9. Deliberate limitations

- The agent does not submit reports to any bug bounty platform. It produces drafts for
  human review.
- The agent does not create accounts unless an engagement explicitly supplies test
  identities.
- The agent does not attempt to bypass CAPTCHAs, WAFs, or rate limiting.
- Secrets discovered during analysis are redacted and never replayed against third-party
  services.
- Autonomous execution is capped at L1. Everything above it is a human decision.
