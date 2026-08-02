# AI Driver Architecture

**English** | [繁體中文](AI_DRIVER.zh-TW.md)

ProofClaw treats an AI coding agent as an optional planning and interaction layer. The agent may
translate a request such as “assess this site and explain the report” into typed ProofClaw tool
calls, but it never replaces target scope enforcement, capture isolation, evidence persistence, or
deterministic finding generation.

## Recommended product modes

### Personal local mode

The user signs in to Codex or Claude Code with their own supported subscription and connects a
local ProofClaw MCP server. ProofClaw exposes narrow tools such as:

- `create_assessment(target, preset)`
- `get_assessment(id)`
- `get_report(id, format)`
- `list_findings(project)`

The agent uses the user's existing local session and ProofClaw does not receive or store model
credentials. Target-facing operations still require ProofClaw's authorization acknowledgement,
scope policy, budgets, and audit trail.

### Managed API mode

Server deployments, teams, scheduled jobs, and unattended automation use provider APIs or an
approved enterprise access-token mechanism. Each tenant supplies or is billed for its own model
usage. Personal subscription session files must never be uploaded, shared between users, baked
into containers, or exposed to a public service.

### Manual mode

Every assessment remains available through the Web console and REST API without an AI provider.
AI failure, quota exhaustion, or provider unavailability must not prevent users from running or
reading deterministic assessments.

## Trust boundary

```text
User conversation
       |
Codex / Claude Code / other MCP client
       |  typed MCP tool call
ProofClaw control plane
       |  scope + policy + budgets + audit
Isolated HTTP/browser workers
       |  immutable evidence
Analyzer and report generator
```

Agent output is untrusted input. ProofClaw validates every tool argument and returns structured
results. The agent cannot grant authorization, widen scope, disable evidence capture, select an
unbounded preset, or invoke arbitrary target-facing commands.

## Delivery sequence

1. Stabilize v0.3 discovery, safe active verification, and reports through REST.
2. Add a local stdio MCP server over the stable REST/application contracts.
3. Publish project-scoped setup for Codex and Claude Code.
4. Add resumable assessment resources and progress notifications.
5. Add provider adapters only for optional planner/verifier roles; keep the scanner provider-neutral.

This sequence keeps the core usable without AI and prevents provider-specific behavior from
becoming part of the security boundary.
