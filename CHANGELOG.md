# Changelog

[繁體中文](CHANGELOG.zh-TW.md) | **English**

Notable changes are documented here. The format follows Keep a Changelog concepts and semantic versioning once versioned releases begin.

## Unreleased

## [0.5.0] - 2026-08-03

### Added

- Added disposable Playwright Chromium sessions with in-memory login secrets, per-run browser
  contexts, download/service-worker blocking, outbound host filtering, and guaranteed cleanup.
- Added digest-bound, operator-reviewed query/header/path mutation plans using only benign marker,
  empty, boundary, and type-mismatch strategies.
- Added deterministic CORS, authentication, authorization, and input-validation comparisons.
- Added engagement-scoped Approval Presets authored by an approver and applied by an operator;
  each application still creates an exact, expiring, single-execution Approval.
- Added Planner/Operator/Verifier automation plan and verification endpoints with audit events.
- Added a dependency-light stdio MCP server with six tools for Codex, Claude Code, and compatible
  clients.

### Changed

- Added Alembic revision `0008_approval_presets` and advanced release metadata to `0.5.0`.
- The isolated Worker image now installs Playwright and its Chromium runtime dependencies.

### Security

- Browser credentials remain in memory and are excluded from results; browser contexts and
  processes are destroyed after each run.
- Mutation plans are reviewable and digest-bound. Sensitive header mutation and unreviewed
  input-validation execution are rejected.
- MCP never receives model-provider credentials and cannot bypass scope, policy, or approvals.

## [0.4.0] - 2026-08-02

### Added

- Added an authenticated operator Finding review endpoint with explicit review statuses,
  evidence-required verification, optimistic version checks, and immutable `finding.reviewed`
  audit events.
- Added SARIF 2.1.0 direct engagement reports and idempotent immutable SARIF report exports.
- Added Web console SARIF downloads for current and persisted assessment results.
- Added bilingual Finding review and SARIF reporting documentation.

### Changed

- Added Alembic revision `0007_sarif_exports` and expanded the report export format contract.
- Advanced Python, Web, User-Agent, and release metadata versions to `0.4.0`.

### Security

- Finding review changes control-plane metadata only; it does not authorize new target-facing
  actions or widen scope.
- SARIF contains metadata and locations, never raw HTTP bodies. Immutable downloads still
  require the evidence-reader role and pass SHA-256 verification.

## [0.3.1] - 2026-08-02

### Changed

- Expanded both README files with a version-by-version major update table covering v0.1.0 through v0.3.1.
- Corrected Quick Start and current-capability wording to describe the v0.3 safe automated mode accurately.
- Synchronized release metadata, package versions, and the default assessment User-Agent to `0.3.1`.

This is a documentation and release-metadata patch; target-facing behavior remains the same as v0.3.0.

## [0.3.0] - 2026-08-02

### Added

- Added semantic OpenAPI 3.x and Swagger 2.0 operation inventory with bounded document and operation limits.
- Added an explicit `active-safe` assessment mode that automatically verifies only parameterless GET/HEAD operations and never sends documented write methods.
- Added evidence-backed CWE-306 candidate detection when an operation declares authentication but accepts an anonymous request with a successful response.
- Added API operation and active-probe summaries to JSON, Markdown, HTML, and Web console results.

### Changed

- Safe automated testing is now the Web console default; discovery-only mode remains one selection away.
- Assessment results expose active-probe counts and independent discovery/active budget truncation status.
- Advanced the Python and Web package versions to `0.3.0`.

### Security

- Every semantic probe remains same-origin or explicitly scoped, is rechecked immediately before DNS-pinned execution, and is bounded to ten operations and 45 seconds.
- Path/query/header/cookie parameters, templated paths, POST/PUT/PATCH/DELETE and all unknown methods are inventory-only and never automatically executed.
- Authentication findings remain candidates with medium confidence because an HTTP 2xx alone cannot prove unauthorized data exposure.

## [0.2.0] - 2026-08-02

### Added

- Added bounded same-origin crawling with Safe (5), Fast (15), and Deep (30) page/request presets and hard time budgets.
- Added deterministic discovery from HTML links, assets and forms, robots and sitemap references, JavaScript API paths, and conventional security/OpenAPI/GraphQL locations.
- Added Finding severity, confidence, and actionable remediation fields with an Alembic migration.
- Added discovery summaries and a standalone escaped HTML report protected by a restrictive Content Security Policy.
- Added a provider-neutral AI driver architecture for future Codex, Claude Code, and other MCP clients.

### Changed

- Assessment results and history now aggregate every captured discovery page into one Engagement report and evidence chain.
- The Web console now offers discovery presets, pages-scanned status, severity badges, remediation guidance, and HTML preview.
- Advanced the Python and Web package versions to `0.2.0`.

### Security

- Every discovered URL must remain same-origin, match the persisted Engagement scope, pass DNS/private-address policy again, and stay inside fixed page, request, time, response-size, and timeout budgets.
- Crawling remains credential-free, GET-only, redirect-disabled, and form-submission-disabled.
- AI agents remain outside the security boundary and cannot grant authorization or widen scope.

## [0.1.0] - 2026-08-02

### Added

- Delivered the first user-completable workflow: start the local Compose stack, enter one authorized public URL, run a bounded assessment, review Finding details and Evidence integrity, and download JSON or Markdown reports.
- Added automatic first-run Project setup, a remembered browser authorization acknowledgement, visible three-stage progress, inline failure recovery, and optional advanced Project organization.
- Added a product-outcome roadmap that requires every milestone to finish a usable vertical workflow before expanding infrastructure.

### Changed

- The loopback-only local Compose profile now enables the bounded passive assessment path by default; the application-level and non-local default remains disabled.
- The dashboard primary action now starts an assessment instead of requiring users to understand or create internal Project and Engagement records first.
- Advanced Scope, persistence, DNS pinning, limits, and evidence-chain controls remain enforced behind the simplified interface.
- Advanced the Python and Web package versions to `0.1.0` and moved the project status from pre-alpha to alpha.

### Security

- The simple path still performs only one credential-free GET against the exact hostname, scheme, port, and path derived from the submitted URL.
- DNS candidates, private-address policy, proxies, redirects, response size, timeout, report metadata, and Evidence-chain integrity remain independently enforced.
- Shared or production deployments still require explicit enablement and authentication; crawling, forms, login, active payloads, exploitation, and arbitrary tools remain unavailable.

## [0.0.21] - 2026-08-02

### Added

- Added a narrow Worker executor for scope-bound, credential-free `public_page_read` L0 GET/HEAD requests using the existing DNS-pinned HTTP transport.
- Added a protected HTTP action request contract with capability, parameter-digest, timeout, header, method, and decoded-response-size validation before network I/O.
- Added a real explicitly scoped loopback transport test and an end-to-end Worker capture-to-Evidence integration test covering Action completion and hash-chain verification.

### Changed

- Advanced the project and Web package version to `0.0.21` and documented the executor boundary in English and Traditional Chinese.
- Unsupported Worker actions now fail with a stable `worker_action_not_supported` policy result instead of the earlier implementation placeholder.

### Security

- The executor disables proxies, validates every resolved address, rejects mixed public/private answers, pins a validated IP while preserving TLS hostname checks, refuses redirects, and bounds timeout and response bytes.
- Authorization, cookies, request bodies, POST, login sessions, JavaScript, crawling, browser automation, and arbitrary tools remain outside the contract; unknown transport details are not reflected.
- The official Docker Worker network remains internal and public egress remains disabled pending a separately reviewed controlled-egress design and startup integration.

## [0.0.20] - 2026-08-02

### Added

- Added a strict inline `http-v1` Worker capture contract for one GET/HEAD response with canonical targets, allowlisted request headers, bounded headers and body, body digest, capture time, and duration.
- Added trusted control-plane capture ingestion that reconstructs the existing HTTP evidence contract, rechecks Action parameters and Engagement scope, allocates the Evidence ID, and appends canonical content to the transactional hash chain.
- Added focused protocol, Worker manager, lifecycle, persistence, parameter-drift, expired-scope, target-binding, duration, base64, digest, redirect, HEAD-body, and decoded-size tests.

### Changed

- Successful Worker responses may contain either persisted Evidence IDs or one inline HTTP capture, never both; accepted inline content is replaced with a control-plane Evidence ID before the lifecycle response is returned.
- Advanced the project and Web package version to `0.0.20` and added bilingual Worker capture-ingestion documentation.

### Security

- Workers cannot choose Evidence IDs or write directly to evidence storage. Inline bodies are excluded from representations and never copied into audit payloads.
- The control plane independently checks target and duration binding, protected parameter digests, persisted time-aware scope, redirect rejection, HEAD semantics, decoded byte size, and body SHA-256 before persistence.
- Rejected captures close the Action with a stable safe code and no evidence; the bundled Worker remains network-disabled, so this boundary does not claim target execution.

## [0.0.19] - 2026-08-02

### Added

- Added a bounded Worker stdin entry point that strictly validates one real v1 request and emits a request-bound terminal response without contacting the target or inventing evidence.
- Added source-bound container image identity records containing the commit, image ID, platform, Dockerfile hash, and any available repository digest alongside existing SBOM artifacts.
- Added an explicitly enabled Linux/Docker end-to-end test that exercises the production Engine adapter and complete hardened Worker lifecycle with a digest-pinned image.

### Changed

- Advanced the project and Web package version to `0.0.19` and documented the distinction between protocol verification, local image identity, registry publication, and target-facing execution.

### Security

- Invalid, malformed, empty, and oversized Worker input now produces one fixed non-reflective error; valid input produces a strict `policy_denied` response bound to the original request, engagement, action, and exit code.
- Worker protocol verification performs no target network request and returns no evidence or artifact identifiers, so an infrastructure milestone cannot be mistaken for a successful assessment.
- CI images carry an OCI source-revision label that must match the identity record; local image IDs are explicitly kept distinct from registry publication digests.

## [0.0.18] - 2026-08-02

### Added

- Added an explicitly enabled Docker Engine API v1.44 backend over one configured local Unix socket, injected only into the separate Engine process.
- Added independent allowlisting for one digest-pinned Worker image and one dedicated internal network, plus Linux, API-version, seccomp, image, and network readiness checks.
- Added fixed-field create, stdin-only request attachment, start, bounded wait/log decoding, stop, ownership-filtered inventory, and idempotent forced removal operations.
- Added focused mocked-Engine tests for full lifecycle behavior, exact Docker request hardening, ownership enforcement, attach cleanup, response bounds, raw-stream framing, safe status mapping, readiness failures, process injection, and configuration gates.

### Changed

- Engine application lifespan now closes backend transport resources, and the process entry point injects the Docker adapter only when its separate policy is complete.
- Advanced the project and Web package version to `0.0.18` and added bilingual Docker backend documentation and runtime status updates.

### Security

- Docker create requests have no caller-controlled command, entrypoint, environment, bind mount, device, published port, namespace, privilege, added capability, daemon URL, or proxy field.
- Every post-create operation re-inspects the immutable owner label and hardened image, network, root-filesystem, capability, privilege, and security-option state before touching the container.
- Docker JSON, declared and streamed bytes, attach headers, multiplexed log framing, and Worker output are bounded; daemon messages, socket paths, payloads, and opaque IDs remain out of public failures.
- Failed stdin attachment force-removes the newly created container and anonymous volumes; create conflicts are idempotent only for the exact same owned request.

## [0.0.17] - 2026-08-02

### Added

- Added an explicitly enabled, separately launched FastAPI Engine gateway server for the existing readiness, create, start, wait, stop, forced removal, and ownership inventory contract.
- Added a narrow injectable privileged-backend protocol, safe backend error categories, and a disabled backend that keeps readiness fail-closed until the reviewed Engine adapter exists.
- Added server settings for loopback binding, a secret Bearer token, request-size limits, concurrent-operation limits, and bounded queue admission.
- Added focused server tests plus a real in-memory `HttpDockerEngineGateway` client-to-server lifecycle test.

### Changed

- Added the `vuln-proof-claw-engine` process entry point and documented the separate trust boundary and environment configuration in English and Traditional Chinese.
- Advanced the project and Web package version to `0.0.17` and updated runtime status documentation to distinguish the completed gateway service boundary from the pending privileged Engine adapter.

### Security

- Authentication now runs before body parsing and privileged admission. Both declared and streamed request sizes are bounded before strict schema validation.
- Concurrent privileged operations are semaphore-limited with a short queue timeout, and Worker output is checked again at the server boundary.
- Backend errors are reduced to stable public codes; unexpected exception messages, Engine details, opaque references, payloads, and secrets are not exposed through responses or representations.

## [0.0.16] - 2026-08-02

### Added

- Added an authenticated, bounded HTTP `RestrictedDockerEngine` client covering readiness, create, start, wait, stop, forced removal, and ownership-filtered inventory.
- Added strict gateway wire models that independently revalidate the Worker protocol payload, digest-pinned image, Worker/name/request labels, non-root user, hard resource ceilings, immutable privilege flags, and required tmpfs storage.
- Added fail-closed Engine gateway settings for HTTPS or explicit loopback IP origins, distinct 32–4096 character Bearer secrets, optional private CA bundles, timeouts, and response ceilings.
- Added 24 focused gateway tests for authentication, lifecycle integration, HTTPS and loopback policy, bounded streaming and decoding, status classification, malformed responses, direct schema bypass attempts, and secret-safe failures.

### Changed

- Engine references now travel only as opaque JSON values rather than URL path components, redirects and ambient proxy discovery are disabled, and no mutating operation is blindly retried.
- Advanced the project and Web package version to `0.0.16` and updated the bilingual runtime roadmap and security documentation.

### Security

- Both declared `Content-Length` and actual streamed response bytes are bounded before strict JSON parsing; decoded Worker output is checked against its separate limit.
- Gateway response bodies and HTTP details never enter safe exceptions. Authentication, conflict, rejection, invalid-response, limit, and availability failures use stable codes.
- Enabling the runtime requires complete gateway credentials in every environment; production additionally requires API authentication readiness, and the Engine token must differ from API role tokens.

## [0.0.15] - 2026-08-02

### Added

- Added a complete restricted `DockerWorkerRuntime` lifecycle over a narrow privileged Engine interface, including create, start, bounded wait, stop, idempotent removal, and labeled inventory.
- Added immutable policy-derived runtime identities, digest-pinned image validation, dedicated-network validation, capability allowlists, and configurable CPU, memory, PID, timeout, request, output, tmpfs, and stop ceilings.
- Added 32 focused runtime tests covering hardened container specs, lifecycle integration, protocol and exit-code validation, inventory ownership, unsafe configuration, metadata injection, oversized I/O, and safe Engine failures.
- Added bilingual restricted-runtime boundary documentation and explicit fail-closed environment settings.

### Changed

- Worker requests now enter containers only as bounded strict-protocol stdin; the Engine request has no arbitrary command, entrypoint, environment, host mount, device, privileged, host-network, or added-capability fields.
- Runtime inventory labels now bind owner, Worker ID, request ID, creation time, and exact policy identity.
- Advanced the project and Web package version to `0.0.15`.

### Security

- Every emitted container spec requires non-root execution, a read-only root filesystem, `cap_drop=ALL`, `no-new-privileges`, init, and `noexec,nosuid,nodev` tmpfs storage.
- Runtime enablement is explicit, digest-pinned policy creation fails closed, production enablement requires API authentication readiness, and raw Engine details, output, and references stay out of safe exceptions and representations.

## [0.0.14] - 2026-08-02

### Added

- Added a runtime-neutral inventory contract with immutable Worker/request ownership labels and opaque privileged references.
- Added a serialized orphan-resource janitor that preserves in-flight work, applies a bounded grace period to unregistered resources, and removes terminal, stale, or mismatched resources.
- Added ordered restart recovery that first marks abandoned Worker executions and Actions lost, then cleans their runtime resources.
- Added focused coverage for live-resource preservation, restart cleanup, binding and runtime-identity mismatches, duplicate inventory entries, cleanup retries, safe errors, and optimistic update conflicts.

### Changed

- Worker IDs are now allocated before runtime creation and passed into the adapter so ownership labels cannot be attached after the fact.
- Advanced the project and Web package version to `0.0.14` and documented the runtime cleanup contract in English and Traditional Chinese.

### Security

- Runtime references remain process-local and are excluded from durable rows, audit payloads, result representations, and safe exceptions.
- Inventory failures and cleanup exceptions are reduced to stable error codes; resources with non-terminal durable bindings are never destroyed by the janitor.

## [0.0.13] - 2026-08-02

### Added

- Added a newest-first, paginated passive-assessment history API with optional project filtering, normalized targets, terminal timestamps, Evidence/Finding counts, safe failure codes, and report links.
- Added a persistent Web assessment-history workspace with project filtering, localized timestamps, explicit state labels, result counts, error visibility, and authenticated JSON/Markdown report downloads.
- Added API integration coverage for successful, failed, empty, and project-filtered assessment histories, plus frontend URL-contract coverage.

### Changed

- Assessment-history count aggregation now uses correlated database queries and one bounded audit lookup per page instead of per-row relationship loading.
- Responsive history rows collapse to touch-friendly cards on small screens while preserving visible status text and keyboard-operable report actions.

### Security

- Listing assessment history is read-only and never initiates target traffic. Existing API authentication still protects normalized targets and report references.
- Failure history exposes only the existing stable error code from the audit trail; transport exceptions and sensitive raw Evidence remain unavailable through this endpoint.

## [0.0.12] - 2026-08-01

### Added

- Added a bilingual Web assessment workspace that creates a narrow 24-hour L0 Engagement from an explicitly authorized URL and starts the passive assessment pipeline.
- Added tab-scoped operator Bearer-token support for authenticated deployments, persisted only in `sessionStorage` with explicit clear controls.
- Added assessment result state, Evidence/Finding counts, authenticated JSON/Markdown report downloads, and stable `#assessments` deep linking.
- Added frontend unit coverage for URL/scope preparation, IP-literal rejection, credential rejection, API authentication headers, stable API errors, idempotency keys, and navigation restoration.

### Changed

- The Web CI job now runs frontend unit tests before TypeScript checking and production asset verification.
- Improved keyboard navigation, visible focus, touch target sizing, reduced-motion handling, responsive assessment layout, and authorization/loading feedback.

### Security

- The UI removes query strings and fragments before assessment, rejects embedded URL credentials, unsupported schemes, and IP literals, and requires an explicit authorization confirmation. Private and IP-literal targets require manually reviewed API scope.
- UI visibility remains non-authoritative: the server continues to enforce authentication, role, scope, policy, DNS, transport, and response limits.

## [0.0.11] - 2026-08-01

### Added

- Added an opt-in passive URL assessment API that creates a policy-checked Action, captures evidence, derives deterministic findings, and exposes report links.
- Added a proxy-free HTTP(S) transport with DNS pinning, TLS hostname verification, redirect rejection, streaming response limits, and explicit private-CIDR opt-in.
- Added response analysis for transport security, browser hardening headers, version disclosure, and sensitive-cookie flags.
- Added idempotent replay, persisted result lookup, truthful execution readiness, bilingual operating documentation, and end-to-end negative-path tests.

### Security

- Target traffic remains disabled by default and production enablement requires API authentication readiness.
- Mixed public/private DNS answers, denied networks, unexpected private addresses, invalid content lengths, oversized bodies, and target changes fail closed.
- The preview sends only GET requests with fixed `Accept` and configured `User-Agent` headers; credentials, cookies, redirects, arbitrary methods, and exploit payloads remain unavailable.

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
