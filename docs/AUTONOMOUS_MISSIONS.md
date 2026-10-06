# Running Autonomous Missions

How to define, register, and operate a long-running autonomous research mission.
For the design and the phase plan, see [AUTONOMOUS_AGENT_ARCHITECTURE.md](AUTONOMOUS_AGENT_ARCHITECTURE.md).

---

## 1. Write the engagement definition

An engagement file is the written record of what a program authorized. It is the only
source of scope, program rules, and rate limits. Nothing in the system infers an
authorization boundary, and the agent can never widen one.

Start from [`examples/engagement.yaml`](../examples/engagement.yaml).

```yaml
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z

scope:
  include:
    - "*.example.com"       # strict subdomains only
    - "api.example.com"     # the apex must be listed explicitly
  exclude:
    - "status.example.com"
    - "*.thirdparty.example"
  allowed_ports: [443]
  allowed_schemes: ["https"]

program:
  program_name: Example Bug Bounty
  prohibited_testing: ["denial of service", "social engineering"]

rate_limits:
  requests_per_minute_per_domain: 5

risk_policy:
  maximum_risk: L1
  auto_execute_l1: true
  maximum_autonomous_risk: L1
```

### Scope rules worth knowing

- `*.example.com` matches **strict subdomains only**. It does not grant `example.com`;
  list the apex separately if the program authorizes it.
- Deny rules are evaluated **before** allow rules and always win, including over an
  explicitly allowed hostname.
- A wildcard whose base is a public suffix (`*.co.uk`, `*.com`) is refused.
- Wildcards never apply to IP literals.
- Timestamps must be timezone-aware. Outside the window every target is denied
  (`engagement_not_started` / `engagement_expired`).

## 2. Validate before registering

```bash
vuln-proof-claw mission validate examples/engagement.yaml
```

This resolves the file to the normalized scope the policy engine will actually enforce
and prints it. Read it: this is the authorization, not what you intended to write.

Add `--json` for a stable `v1` document.

## 3. Register the engagement and mission

```bash
vuln-proof-claw mission create examples/engagement.yaml
```

This creates the project, engagement, normalized scope, and a mission in `pending`
state. It prints the `mission_id` you will need for the remaining commands.

## 4. Operate the mission

```bash
vuln-proof-claw mission status <mission_id>
vuln-proof-claw mission pause  <mission_id>
vuln-proof-claw mission resume <mission_id>
vuln-proof-claw mission stop   <mission_id> --kill-switch
```

`status` reports mission state, the active run and cycle index, lead counts by status,
and the size of the known attack surface.

`pause` stops new cycles without discarding state. `--kill-switch` additionally engages
a flag that blocks every future cycle regardless of state.

---

## 5. What a cycle does

```
observe      snapshot the attack surface
detect       emit ChangeEvents; reawaken stale leads whose surface changed
age          mark long-untouched leads stale
rank         order eligible leads by a deterministic priority
work         for each lead, within budget:
               recall memory -> plan -> validate -> policy -> execute -> record
```

A lead is **eligible** only when all of these hold:

- its status is `new`, `queued`, or `waiting`
- it is not blocked awaiting a human decision
- its attempt count is below `maximum_lead_attempts`
- its cooldown has elapsed
- **if it has failed before, new evidence has arrived since the last attempt**

That last rule is why the agent does not re-run the same failed hypothesis on a timer.
"New evidence" means stored observations or change events — never the agent's own
assertion that a retry is worthwhile.

## 6. Safety properties you can rely on

| Property | Where it is enforced |
|---|---|
| Nothing executes without an `ALLOW` policy decision | `policy/decision.py:decide_action`, re-run by `execution/authorization.py` |
| Unattended execution is capped at L1 | `domain/autonomous.py:Mission.__post_init__` |
| A planner cannot choose its own risk level | `agent/planner.py:validate_plan`, then `decide_action` |
| Out-of-scope targets are denied | `policy/scope.py:evaluate_scope`, default-deny |
| An interrupted attempt still counts | `agent/leads.py:begin_attempt` |
| Only verification creates a finding | `agent/leads.py:promote_to_finding` |
| Destructive proof is never attempted | `verification_verdict` → `needs_manual_review` |
| Rate limits are checked before proposing | `agent/budget.py:BudgetGate.permits_request` |

On HTTP 429 or observed WAF blocking the controller backs off and lowers its effective
rate. It does not attempt to circumvent the control, and CAPTCHA solving is out of scope
by design.

## 7. Crash and reboot recovery

No in-memory state is authoritative. On startup the controller:

1. marks any run whose heartbeat expired as `interrupted`;
2. returns leads stuck in `investigating` to `queued`, with the attempt already counted;
3. resumes from the persisted cycle index.

```python
controller.recover(watchdog_seconds=900)
run = controller.start_run()
report = controller.run_cycle(run)
```

## 8. Current limitations

- Autonomous execution currently drives the passive HTTP capture path
  (`public_page_read`, L0). Recon tool adapters land in Phase 2.
- Change detection records additions. Removal detection and richer typed diffs are
  Phase 6.
- The Phase 1 planner is deterministic and makes no model calls. The LLM planner,
  its structured prompt, and token accounting are Phase 7.
- There is no HTTP dashboard yet; `mission status` is the operator view until Phase 8.
- Reports are produced by the existing reporting module. Bug bounty draft generation is
  Phase 9.
