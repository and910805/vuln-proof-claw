# Roadmap

[繁體中文](ROADMAP.zh-TW.md) | **English**

Roadmap items describe intent, not guaranteed release dates.

## Delivery rule

Each milestone must end in a user-completable workflow, not only an internal
module. Safe defaults stay enforced in the control plane while common users see
one primary action and optional advanced settings. Infrastructure work is pulled
forward only when it unblocks the next usable workflow.

## Phase 0 — Foundation

- Python project, CLI, API health contracts, PostgreSQL, Docker Compose.
- Domain, policy, approval, and evidence primitives.
- Web console foundation: React/TypeScript shell, dashboard summary, project creation, tab-scoped operator access, authorized passive assessment wizard, persistent project-filtered history, report downloads, and bilingual UI.
- Bilingual governance, CI, supply-chain checks, and worker protocol.

## v0.1 — Usable Passive MVP

Version 0.1.0 is the first user-completable release: one local Compose command,
one URL field, a remembered authorization acknowledgement, automatic Project and
Engagement setup, bounded DNS-pinned capture, Finding details, evidence-integrity
status, persistent history, and JSON/Markdown reports.

- Common path: enter an authorized public URL, run, review, download.
- Advanced path: choose Projects and use explicit API Scope definitions.
- Background controls: exact target Scope, DNS pinning, no proxy, bounded bytes and
  timeout, no redirects, conservative GET-only analysis, and evidence hash chains.
- Explicit limitation: no crawl, login, form submission, active payload, exploit,
  or automatic vulnerability confirmation yet.

## v0.2 — Useful Web Discovery

Version 0.2.0 delivers the first bounded multi-page workflow: same-origin extraction,
scope and DNS re-evaluation for every request, per-page Evidence, aggregate Findings,
and fixed Safe (5), Fast (15), and Deep (30) page/request/time budgets.

- Discovery from HTML links, assets and forms, `robots.txt`, sitemap locations,
  JavaScript API paths, OpenAPI/Swagger, GraphQL, and common security files.
- Findings include severity, remediation, confidence, and an escaped HTML preview.
- Remaining discovery depth: richer sitemap index handling, content-aware duplicate
  suppression, and crawl progress streaming.

## v0.3 — Authorized Active Testing

Version 0.3.0 delivers the first controlled active vertical slice: semantic OpenAPI
inventory and automatic verification of parameterless read-only operations. The Web
console exposes one safe automated mode while the control plane retains per-request
scope, DNS, evidence, request-count, and time enforcement.

- Delivered: OpenAPI 3.x/Swagger 2.0 inventory, GET/HEAD-only safe probes, declared-auth
  anomaly candidates, active budget status, and report/UI integration.
- Remaining v0.3.x: controlled container egress, registry-published Worker digest,
  isolated browser, authenticated sessions, reviewed parameter tests, and service discovery.
- State-changing checks require reusable approval presets before they can be exposed.

## v0.4 — Autonomous Core

- Planner, Operator, and independent Verifier with budgets and stopping conditions.
- Live progress, interactive approvals, evidence viewer, finding review, and exports
  for HTML, SARIF, and bug-bounty workflows.
- Multi-provider registry and capability detection.
- A local ProofClaw MCP server for Codex, Claude Code, and other clients following
  [AI Driver Architecture](docs/AI_DRIVER.md); managed automation continues to use
  provider APIs or approved enterprise access tokens.

## v1.0 — Stable Open Source

- Stable REST and plugin APIs, upgrade documentation, security review, signed images, and SBOMs.

## Later

Internal networks, Active Directory, cloud, mobile, teams, distributed workers, and a signed plugin registry require separate approved designs.
