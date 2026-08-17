# Changelog

[繁體中文](CHANGELOG.zh-TW.md) | **English**

Notable changes are documented here. The format follows Keep a Changelog concepts and semantic versioning once versioned releases begin.

## Unreleased

## [0.1.0] - 2026-08-17

First tagged **Evidence Core** milestone, consolidating the `0.0.1`–`0.0.16` preview series.

### Highlights

- Persisted Projects, Engagements, normalized Scopes, and the Action lifecycle with an immutable, actor-attributed audit trail.
- Authenticated approval workflow with single-use, execution-time approval consumption.
- Tamper-evident evidence hash chains, integrity-aware reports, and immutable JSON/Markdown report exports with a separately authorized raw-evidence reader.
- A hardened, fail-closed disposable-worker platform: durable registry, restart reconciliation, an orphan-runtime janitor, and a concrete Docker runtime that drops all capabilities, forbids new privileges, and blocks internet egress.
- Real scope-checked HTTP capture whose evidence is persisted through the control plane into the tamper-evident chain.
- A disposable Playwright browser runtime that captures authentication sessions into the engagement-bound session registry.

### Notes

- Target-facing execution remains disabled by default; the Docker worker and browser runtimes activate only when `docker.runtime_enabled` is set.
- Every component was verified end to end against a live Docker daemon.

## [0.0.16] - 2026-08-17

### Added

- Added a disposable Playwright browser worker that performs one form login and captures the resulting storage state.
- Added a `BrowserSessionCaptureCoordinator` that scope-checks the login target, runs the browser worker, and persists the captured session through the authentication session registry.
- Added a shared `SessionCaptureEnvelope` and `LoginInstruction` wire format and a `docker/browser` image built on Python 3.12 with a pinned Chromium.
- Added a Docker-gated integration test that logs into a disposable local form and confirms the session cookie is captured.

### Security

- Login credentials establish the session only; they never enter the persisted material or the audit trail.
- Only the captured storage state is persisted, as tamper-evident session material with redacted cookie and storage key names.
- The browser worker drops all Linux capabilities, gains no new privileges, and is attached only to the isolated worker network, so it cannot reach the public internet.
- Login targets outside the engagement scope, failed captures, and runtime failures fail closed with stable error codes and persist nothing.

## [0.0.15] - 2026-08-16

### Added

- Added a `WorkerCaptureCoordinator` that authorizes a queued Action, runs a disposable worker, and persists the captured response as tamper-evident evidence before transitioning the Action.
- Added a shared `CaptureEnvelope` worker-to-control-plane wire format carrying the full bounded response.
- Made the worker emit a `CaptureEnvelope` (status, headers, and base64 body) alongside its terminal response.
- Added a Docker-gated integration test covering the worker capture runner against a live local target.

### Security

- The worker never touches the database; the control plane holds all authority and owns evidence persistence.
- Persisted evidence enters the per-engagement hash chain and is verified end to end; a live run confirmed the recovered body matches the target and the chain validates.
- Worker runtime failures, failed captures, and unknown or unauthorized Actions fail closed to a FAILED Action with a stable error code.

## [0.0.14] - 2026-08-16

### Added

- Replaced the placeholder worker entry point with a disposable worker that performs one bounded HTTP capture and emits a terminal `WorkerResponse`.
- Re-evaluates the engagement scope for the target inside the sandbox before any request is made.
- Made `DockerWorkerRuntime.wait` tolerant of diagnostic output by treating the last parseable response line as authoritative.
- Added a Docker integration test that runs the real worker against a local target and confirms the internet is unreachable.

### Security

- The worker performs a single redirect-free `GET`, sends no credentials, and bounds the response body.
- Out-of-scope targets, redirects or target changes, timeouts, oversized bodies, and transport failures each map to a stable, detail-free error code.
- A live end-to-end run confirmed the worker captures an in-scope local target but cannot reach an internet host on the isolated network.

## [0.0.13] - 2026-08-16

### Added

- Added a concrete Docker worker runtime that fills the `WorkerRuntime` seam with hardened disposable containers.
- Added a fail-closed manager factory that returns the disabled worker manager unless the runtime is explicitly enabled.
- Added an injected Docker CLI runner that keeps the runtime unit-testable, plus an opt-in live Docker integration test.
- Added ownership-labelled containers and a `list_owned` capability the orphan-runtime janitor can reclaim.

### Security

- Launches every worker with all Linux capabilities dropped, a read-only root filesystem, no new privileges, and process, memory, and CPU ceilings.
- Attaches workers only to the isolated worker network, so a worker cannot reach the public internet.
- Refuses to construct or execute while `docker.runtime_enabled` is false, keeping target-facing execution disabled by default.
- Surfaces stable, detail-free error codes for create, start, wait, cancel, remove, and list failures.

## [0.0.12] - 2026-08-16

### Added

- Added an engagement-bound registry for captured browser authentication sessions with Alembic revision `0006_authentication_sessions`.
- Added a session service that captures, revokes, and releases authentication material transactionally with audit events.
- Added optimistic-version revocation and time-and-state-bounded usability for authentication sessions.

### Security

- Keeps captured material out of the domain model, logs, and audit payloads; only a digest, byte size, and redacted key names are retained.
- Releases material only to the owning engagement through a usable session, recomputing size and SHA-256 before release.
- Fails closed for revoked, expired, cross-engagement, oversized, or tampered sessions.

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
