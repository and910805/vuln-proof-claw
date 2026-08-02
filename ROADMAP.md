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

- Bounded same-origin crawler with page/request/time budgets.
- `robots.txt`, sitemap, JavaScript URL, OpenAPI, GraphQL, and common security-file discovery.
- Deduplicated findings with severity, remediation, confidence, and HTML report preview.
- Safe/Fast/Deep presets; detailed limits remain optional advanced settings.

## v0.3 — Authorized Active Testing

- Controlled container egress, registry-published Worker digest, and startup integration.
- Curated non-destructive active checks, isolated browser, authenticated sessions,
  OpenAPI parameter tests, and basic service discovery.
- Reusable approval presets for actions that can affect target state.

## v0.4 — Autonomous Core

- Planner, Operator, and independent Verifier with budgets and stopping conditions.
- Live progress, interactive approvals, evidence viewer, finding review, and exports
  for HTML, SARIF, and bug-bounty workflows.
- Multi-provider registry and capability detection.

## v1.0 — Stable Open Source

- Stable REST and plugin APIs, upgrade documentation, security review, signed images, and SBOMs.

## Later

Internal networks, Active Directory, cloud, mobile, teams, distributed workers, and a signed plugin registry require separate approved designs.
