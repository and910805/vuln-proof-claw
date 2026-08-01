# Roadmap

[繁體中文](ROADMAP.zh-TW.md) | **English**

Roadmap items describe intent, not guaranteed release dates.

## Phase 0 — Foundation

- Python project, CLI, API health contracts, PostgreSQL, Docker Compose.
- Domain, policy, approval, and evidence primitives.
- Web console foundation: React/TypeScript shell, dashboard summary, project creation, and bilingual UI.
- Bilingual governance, CI, supply-chain checks, and worker protocol.

## v0.1 — Evidence Core

Current preview: persisted normalized engagement scopes, Flow/Task/Action proposal APIs, authenticated single-action approval decisions, execution-time approval consumption, an immutable audit trail, transactional raw evidence chains, separately authorized and audited raw-evidence reads, integrity-aware reports, immutable report exports, database re-verification, a fail-closed HTTP capture contract, and a durable disposable Worker lifecycle registry with restart reconciliation are implemented. A concrete restricted runtime, orphan-runtime janitor, and browser authentication sessions remain in progress.

- Project, Engagement, Scope, and Action persistence.
- Structured HTTP request/response capture.
- Disposable Worker lifecycle (durable registry and fail-closed restart reconciliation complete; restricted runtime pending).
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
