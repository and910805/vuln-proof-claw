# Changelog

[繁體中文](CHANGELOG.zh-TW.md) | **English**

Notable changes are documented here. The format follows Keep a Changelog concepts and semantic versioning once versioned releases begin.

## Unreleased

## [0.0.11] - 2026-08-16

### Added

- Added an orphan-runtime janitor that reclaims disposable-Worker runtime resources with no live in-process owner.
- Added a reapable runtime capability that enumerates and idempotently destroys platform-owned Workers.
- Added a system-level audit helper for control-plane events not bound to a single engagement.
- Exposed the live runtime references a manager still owns so a concurrent sweep never destroys a tracked Worker.

### Security

- Treats every enumerated runtime reference as an orphan after a restart, closing the gap left by unpersisted runtime references.
- Never destroys a reference protected by a live manager, and fails the sweep closed when enumeration fails.
- Records only reference-free reclamation counts in the audit trail, and skips audit writes for no-op sweeps.

## [0.0.10] - 2026-08-01

### Added

- Added a separately configured `evidence_reader` Bearer role for sensitive content access.
- Added audited, engagement-bound raw-evidence downloads that verify the full evidence chain.
- Added idempotent, immutable JSON and Markdown report exports with Alembic revision `0005_report_exports`.
- Added report export listing and integrity-checked download APIs.

### Security

- Operators and approvers cannot retrieve raw evidence or report snapshot content.
- Raw evidence access fails closed when the reader credential is absent or the evidence chain is invalid.
- Report downloads recompute content size and SHA-256 before returning bytes.
- Successful sensitive-content reads append actor-bound audit events without logging payloads.

## [0.0.9] - 2026-08-01

### Added

- Added a durable Worker execution registry with one-to-one Action and request bindings.
- Added Alembic revision `0004_worker_executions` and optimistic lifecycle updates.
- Added restart reconciliation for abandoned `starting` and `running` Worker records.

### Security

- Persists only safe lifecycle metadata; privileged runtime references remain outside the database.
- Converts unrecoverable in-flight Workers and their Actions to explicit `lost` / `worker_lost` terminal states.
- Records startup reconciliation in the immutable engagement audit trail.
- Keeps concrete runtime attachment and target-facing execution disabled by default.

## [0.0.8] - 2026-08-01

### Added

- Added an injected-runtime disposable Worker manager with create, start, collect, timeout, cancellation, and mandatory cleanup states.
- Added durable Action-to-Worker orchestration and lifecycle audit events.
- Added process-safe request replay checks and concurrent collect/cancel handling.

### Security

- Rechecks persisted Action, Scope, policy, and Approval state before a Worker starts.
- Consumes a bound Approval only when the Action moves to `running`.
- Rejects mismatched Worker responses and successful results without same-Action persisted Evidence.
- Keeps the concrete runtime and all target-facing execution disabled by default.

## [0.0.7] - 2026-08-01

### Added

- Added optional API-wide Bearer authentication with distinct operator and approver roles.
- Added authenticated single-Action approval and denial decisions with bounded expiry.
- Added operator cancellation and actor-attributed approval, denial, and cancellation audit events.
- Added approval lookup and execution-time single-use consumption.

### Security

- Approval mutations remain disabled when authentication readiness is false.
- Approval identity is derived from deployment configuration rather than client input.
- Expired, missing, changed, exhausted, or mismatched approvals fail before transport.
- Health probes remain public while authenticated mode protects every other v1 API route.

## [0.0.6] - 2026-08-01

### Added

- Added paginated Flow, Task, Action, and engagement audit-event API contracts.
- Added transactional HTTP action proposals with deterministic risk and scope policy outcomes.
- Added immutable audit events for flow, task, action-proposal, and policy-decision changes.
- Added engagement-scoped idempotency replay and protected-parameter conflict detection.

### Security

- Kept allowed actions queued without exposing target-facing execution.
- Rejected unsafe HTTP methods and credential-bearing headers before action persistence.
- Derived risk and policy results on the server from persisted engagement scope.

## [0.0.5] - 2026-08-01

### Added

- Added an internal, transport-independent coordinator for structured `GET`/`HEAD` capture.
- Bound requests to queued Actions through canonical parameter digests and persisted Scope policy.
- Added bounded canonical HTTP evidence envelopes and explicit transport-failure outcomes.

### Security

- Rejected credentials, cookies, redirects, target changes, oversized bodies, and unsafe methods.
- Kept the concrete network transport disabled until disposable Worker DNS and egress enforcement exists.

## [0.0.4] - 2026-08-01

### Added

- Added transactional raw evidence persistence with canonical metadata and per-engagement chain indexes.
- Added a 10 MiB default payload limit and strict Action-to-Engagement binding.
- Added database-backed evidence-chain recomputation and integrity status in engagement reports.
- Added Alembic revision `0003_evidence_payloads`.

### Security

- Raw evidence remains internal and is not exposed through the unauthenticated pre-alpha API.
- Database verification detects modified content, broken links, missing indexes, and size mismatches.

## [0.0.3] - 2026-08-01

### Added

- Persisted normalized allow/deny scope policies for time-bounded engagements.
- Added engagement create, list, detail, and offline scope-evaluation API contracts.
- Added metadata-only JSON and Markdown engagement reports.
- Added Alembic revision `0002_engagement_scopes` and Evidence Core preview documentation.

### Security

- Scope evaluation remains offline and flags hostname decisions for execution-time DNS rechecks.
- Reports exclude raw evidence and target execution remains fail-closed.

## [0.0.2] - 2026-08-01

### Added

- Added a root `VERSION` marker and consistency coverage for Python and Web package versions.
- Displayed the running API version in the Web console.

### Changed

- Updated local setup instructions to install a security-supported `pip` before auditing dependencies.
- Normalized generated Web asset line endings for reproducible Windows builds.

## [0.0.1] - 2026-07-30

### Added

- Independently designed bilingual platform specification.
- Bilingual Phase 0 implementation plan.
- Python package and initial CLI bootstrap.
- Initial bilingual open-source governance documents.
- Bundled bilingual React/TypeScript Web console with live readiness, dashboard counts, and project creation.
- Versioned dashboard and project REST API contracts.

### Security

- Documented EDR-respecting development policy.
- Defined authorized-use, private-reporting, scope, approval, worker-isolation, and evidence-integrity expectations.
- Kept unavailable target execution visibly locked and enforced all authority on the server side.
