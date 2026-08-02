# Roadmap

[繁體中文](ROADMAP.zh-TW.md) | **English**

Roadmap items describe intent, not guaranteed release dates.

## Phase 0 — Foundation

- Python project, CLI, API health contracts, PostgreSQL, Docker Compose.
- Domain, policy, approval, and evidence primitives.
- Web console foundation: React/TypeScript shell, dashboard summary, project creation, tab-scoped operator access, authorized passive assessment wizard, persistent project-filtered history, report downloads, and bilingual UI.
- Bilingual governance, CI, supply-chain checks, and worker protocol.

## v0.1 — Evidence Core

Current preview: persisted normalized engagement scopes, Flow/Task/Action APIs, authenticated approvals, execution-time approval consumption, an immutable audit trail, transactional evidence chains, separately authorized raw-evidence reads, immutable report exports, a DNS-pinned passive URL assessment pipeline with queryable history, deterministic response-header findings, a durable disposable Worker lifecycle registry, bounded orphan cleanup, a digest-pinned restricted-container policy adapter, both sides of an authenticated bounded Engine-gateway boundary, a fixed-field local Unix-socket Docker Engine adapter, bounded Worker protocol verification, source-bound image identity artifacts, and an opt-in live Worker lifecycle test are implemented. Scoped egress, target-facing worker executor capability, registry digest publication, startup integration, crawler, and browser authentication sessions remain in progress.

- Project, Engagement, Scope, and Action persistence.
- Structured HTTP request/response capture.
- Disposable Worker lifecycle (durable registry, fail-closed restart reconciliation, immutable ownership labels, orphan cleanup, restricted-container spec enforcement, authenticated Engine client/server boundary, fixed-field Docker adapter, protocol verification, image identity artifacts, and opt-in live lifecycle test complete; scoped egress, target executor, registry digest publication, and startup wiring pending).
- Evidence hash chain and Markdown/JSON reports.

## v0.2 — Autonomous Core

- Planner, Operator, and independent Verifier.
- Multi-provider registry and capability detection.
- Approval workflow, budgets, stopping conditions, and audit trail.

## v0.3 — Web/API Capability Baseline

- Crawl, directory, JavaScript, OpenAPI, and GraphQL discovery.
- Authentication differential testing, isolated browser, and basic nmap.
- Restricted shell/Python, curated playbooks, HTML/SARIF/bug-bounty reports.

## v0.4 — Web Experience

- Live flows, interactive approval decisions, evidence viewer, finding review, and report preview.
- Authentication, session hardening, accessibility audit, and production UI deployment controls.

## v1.0 — Stable Open Source

- Stable REST and plugin APIs, upgrade documentation, security review, signed images, and SBOMs.

## Later

Internal networks, Active Directory, cloud, mobile, teams, distributed workers, and a signed plugin registry require separate approved designs.
