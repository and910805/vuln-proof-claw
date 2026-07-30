# vuln-proof-claw Platform Design

**Status:** Approved  
**Date:** 2026-07-30  
**Default branch:** `mainer`  
**License:** MIT  

## 1. Executive summary

vuln-proof-claw is an evidence-driven autonomous Web and API security testing platform for authorized enterprise, red-team, penetration-testing, and vulnerability-research workflows.

The project will be implemented independently. It may adopt architectural ideas from VulnClaw and PentAGI, but it will not be a fork of either project. Any reused MIT-licensed code must retain the applicable copyright and license notices.

The approved delivery strategy is:

> Docker Compose as the core deployment model, a local CLI as the first user interface, and a React Web UI after the core workflow is stable.

The first product phase focuses on Web/API security testing and basic network reconnaissance. Later phases may add internal networks, Active Directory, cloud, mobile, distributed workers, and multi-user collaboration.

### 1.1 Naming conventions

- Repository and distribution name: `vuln-proof-claw`
- CLI command: `vuln-proof-claw`
- Python import package: `vuln_proof_claw`
- Docker image prefix: `vuln-proof-claw`
- Environment variable prefix: `VULN_PROOF_CLAW_`

## 2. Product positioning

### 2.1 Target users

- Enterprise security engineers validating products and internal services.
- Red teams and penetration-testing consultancies conducting authorized engagements.
- Vulnerability researchers and bug bounty hunters who need reproducible evidence for submissions.

### 2.2 Core value proposition

vuln-proof-claw is not primarily a tool for producing a large number of speculative findings. Its core value is producing findings that can be traced to real actions and evidence:

- Every verified finding references persisted evidence.
- Every action is evaluated against an explicit engagement scope.
- High-risk actions require approval.
- Target-facing tools run in isolated, disposable workers.
- Findings must be reproducible or independently validated.

### 2.3 Product principles

1. **Evidence first:** no raw evidence means no verified finding.
2. **Scope before action:** scope enforcement is implemented in code, not only in prompts.
3. **Approval by risk:** actions are classified from L0 through L4.
4. **Isolated by default:** target-facing tools execute inside disposable Docker workers.
5. **Model independent:** the domain and workflow do not depend on one LLM provider.
6. **Reproducible results:** verified findings contain replayable requests or equivalent verification steps.
7. **Human authority:** agents can propose actions, but users and the policy engine retain authority.
8. **Project isolation:** memory and evidence do not cross project boundaries by default.

## 3. Scope and roadmap boundaries

### 3.1 Phase 1 scope

Phase 1 covers:

- Web application security testing.
- HTTP and API security testing.
- Basic network reconnaissance.
- CLI and REST API.
- Docker Compose deployment.
- PostgreSQL persistence.
- Disposable Docker workers.
- Multi-provider LLM support.
- Planner, Operator, and Verifier agents.
- Scope, approval, policy, and audit workflows.
- Evidence hash chains.
- Structured findings and reports.
- A stable tool/plugin interface.

### 3.2 Deferred from Phase 1

- React Web UI.
- Multi-tenant organization and account management.
- Active Directory testing.
- Internal-network lateral movement tooling.
- Cloud and mobile security testing.
- Distributed remote workers.
- Plugin marketplace and public registry.
- Cross-project global memory.
- Full Burp Professional integration.

### 3.3 Long-term roadmap

- **v0.4:** React/TypeScript Web UI.
- **v1.0:** stable APIs, plugin SDK, signed releases, and production-quality documentation.
- **v2+:** internal networks, Active Directory, cloud, mobile, teams, distributed workers, and a plugin registry.

## 4. Architecture

vuln-proof-claw uses a Python modular monolith for the control plane and disposable Docker containers for the execution plane.

```text
┌───────────────────────────────────────────────┐
│                 User Interfaces               │
│        CLI first │ REST API │ Web UI later    │
└───────────────────────┬───────────────────────┘
                        │
┌───────────────────────▼───────────────────────┐
│              vuln-proof-claw Control Plane          │
│                                               │
│ Project & Scope    Flow / Task / Action        │
│ Approval Policy    Agent Orchestrator          │
│ Evidence Catalog   Finding Verification        │
│ Report Generator   Provider Adapters           │
└───────────────┬─────────────────┬─────────────┘
                │                 │
        ┌───────▼──────┐   ┌──────▼───────────┐
        │ PostgreSQL   │   │ Worker Manager   │
        │ State/Index  │   │ Lifecycle/Policy │
        └──────────────┘   └──────┬───────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ Ephemeral Docker Worker   │
                    │                           │
                    │ HTTP/Proxy │ Browser      │
                    │ Web Tools  │ Shell        │
                    │ Evidence Collector        │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ Authorized Web/API Target │
                    └───────────────────────────┘
```

### 4.1 Initial technology choices

- Python 3.12 or later.
- FastAPI for the REST control plane.
- Typer for the CLI.
- Pydantic for schemas and configuration.
- SQLAlchemy 2 and Alembic.
- PostgreSQL.
- Docker SDK for worker lifecycle management.
- HTTPX for structured HTTP operations.
- Playwright for isolated browser automation.
- pytest, Ruff, and mypy or Pyright.
- React and TypeScript beginning in v0.4.

### 4.2 Module boundaries

```text
proofclaw/
├── api/              # REST API
├── cli/              # CLI and API client
├── domain/           # Project, Flow, Action, Finding, Evidence
├── orchestration/    # Agent and workflow coordination
├── policy/           # Scope, risk, approval, audit
├── execution/        # Worker lifecycle and execution protocol
├── evidence/         # Evidence storage, hashing, redaction
├── providers/        # LLM provider adapters and presets
├── tools/            # Structured Web/API tools
├── reporting/        # Markdown, JSON, HTML, SARIF
└── persistence/      # PostgreSQL repositories and migrations
```

These are module boundaries, not separate deployable microservices in Phase 1. The Worker Manager or Agent Orchestrator may be extracted only when operational requirements justify it.

### 4.3 Initial Docker Compose topology

- `proofclaw-api`
- `proofclaw-postgres`
- `proofclaw-worker-manager`
- Per-flow disposable worker containers created by the Worker Manager

Redis, Neo4j, MinIO, Grafana, and other infrastructure are not baseline dependencies. They may be introduced when a measured requirement exists.

## 5. Domain and evidence model

### 5.1 Entity hierarchy

```text
Project
└── Engagement
    └── Flow
        └── Task
            └── Action
                ├── Tool Call
                ├── Evidence
                └── Artifact
```

- **Project:** a customer, product, or research project.
- **Engagement:** a time-bounded and explicitly scoped security assessment.
- **Flow:** a complete testing objective within an engagement.
- **Task:** a planned, executable unit of work.
- **Action:** a concrete operation proposed by an agent or user.
- **Evidence:** immutable raw output associated with an action.
- **Artifact:** a screenshot, HAR file, PoC, download, or generated report.

### 5.2 Evidence requirements

Each evidence record includes:

- Evidence ID and Action ID.
- Tool name and version.
- Normalized input parameters.
- Raw output.
- HTTP request and response where applicable.
- Execution timestamps and duration.
- Worker image and environment metadata.
- Scope-policy decision.
- Approval ID when required.
- SHA-256 digest.
- Previous evidence digest.

The initial tamper-evident chain is:

```text
evidence_hash = SHA256(previous_hash + canonical_metadata + raw_content)
```

Phase 1 does not claim forensic-grade non-repudiation. It provides deterministic integrity verification and modification detection.

### 5.3 Finding lifecycle

```text
candidate
    ↓
pending_verification
    ├── verified
    ├── rejected
    └── needs_manual_review
```

Only the Verifier can promote a finding to `verified`. Promotion requires:

- At least one valid evidence record.
- An affected target, endpoint, and parameter or component.
- An observable security impact.
- Replayable or independently validated behavior.
- A scope-valid action and required approval.
- A valid evidence hash chain.

Verified findings contain:

- Title, vulnerability class, severity, CWE, and optional CVSS.
- Affected assets and endpoints.
- Technical description and impact.
- Reproduction steps.
- Redacted HTTP requests and responses.
- Evidence references.
- PoC or replay definition.
- Remediation guidance.
- Verification status and confidence.

Report redaction does not alter the stored raw evidence.

## 6. Scope, risk, and approval policy

### 6.1 Engagement scope

An engagement may define:

- Allowed hostnames, IP addresses, and CIDRs.
- Allowed ports.
- Allowed and blocked URL paths.
- Testing start and end time.
- Approved identities and test accounts.
- Maximum action level.
- Request-rate and concurrency limits.
- Excluded third-party systems.
- Authorization reference and notes.

### 6.2 Enforcement flow

```text
Agent proposes Action
        ↓
Normalize target and parameters
        ↓
Scope Policy Check
        ↓
Risk Classification
        ↓
Automatic / Approval / Denied
        ↓
Worker execution
```

Policy precedence is:

```text
System permanent-deny rules
    > Engagement deny rules
    > Engagement allow rules
    > User single-action approval
    > Agent proposal
```

### 6.3 Risk levels

| Level | Examples | Default behavior |
|---|---|---|
| L0 | Public pages, `robots.txt`, passive fingerprinting | Automatic |
| L1 | Directory enumeration, nmap, active API probing | Project-configurable |
| L2 | Exploit payloads, password testing, file upload | Approval required |
| L3 | Post-exploitation, privilege escalation, lateral movement | Approval required |
| L4 | Data modification/deletion, persistence, destructive operations | Disabled; explicit project enablement and per-action approval required |

An approval is bound to:

- Engagement.
- Action type.
- Normalized target.
- Parameter summary and digest.
- Risk level.
- Expiration time.
- Permitted execution count.
- Approver and approval timestamp.

Changing a payload, target, or protected parameter invalidates the approval.

### 6.4 Worker security baseline

Workers run:

- As a non-root user.
- With a read-only root filesystem where possible.
- With CPU, memory, PID, and execution-time limits.
- Without a mounted Docker socket.
- Without host home directories or credential stores.
- With a per-flow task directory only.
- With network egress restricted to the engagement scope.
- Without direct access to control-plane LLM credentials.
- As disposable containers destroyed after completion.

Redirects, DNS resolution, proxies, IPv4/IPv6 normalization, and browser subresources must all be checked at the execution boundary.

Target HTML, JavaScript, API responses, files, and tool output are untrusted data. They cannot directly authorize tools or bypass policy.

## 7. Agent workflow

### 7.1 Planner

The Planner:

- Interprets the user goal and engagement scope.
- Creates, orders, and updates structured tasks.
- Replans when evidence changes the current hypothesis.
- Determines when the flow is complete, blocked, or awaiting approval.
- Does not execute target-facing tools.

### 7.2 Operator

The Operator:

- Chooses tools.
- Produces structured Action Proposals.
- Uses tool evidence to select subsequent actions.
- Creates candidate findings.
- Cannot approve actions.
- Cannot mark findings as verified.

### 7.3 Verifier

The Verifier:

- Reviews candidate claims against persisted evidence.
- May propose independent in-scope verification actions.
- Detects same-body responses, false positives, incorrect status assumptions, and unsupported model claims.
- Assigns `verified`, `rejected`, or `needs_manual_review`.
- Produces minimum reproduction steps.

The Verifier receives the candidate claim, engagement scope, and referenced evidence. It does not automatically inherit the Operator's conclusions. It may use a different provider or model.

### 7.4 Execution loop

```text
User Goal
    ↓
Planner creates Tasks
    ↓
Operator proposes Action
    ↓
Policy Engine
    ├── denied ─────→ Record + Replan
    ├── approval ───→ Pause + Ask User
    └── allowed ────→ Worker Execution
                           ↓
                       Evidence
                           ↓
              ┌────────────┴────────────┐
              │                         │
        Continue Task             Candidate Finding
              │                         ↓
              └──────────────────→ Verifier
                                        ↓
                     verified / rejected / manual review
```

### 7.5 Memory

- **Execution context:** recent messages and bounded tool-result previews.
- **Evidence store:** complete raw outputs that survive context compression.
- **Project memory:** verified assets, endpoints, technology, and findings.

Large bodies and logs remain in evidence storage. Agents use high-signal summaries and evidence IDs, then search or page raw evidence when required.

## 8. LLM provider architecture

Phase 1 includes a provider registry rather than a single-provider implementation.

Supported provider families:

- OpenAI.
- Anthropic.
- Google Gemini.
- Azure OpenAI.
- AWS Bedrock.
- Ollama.
- OpenRouter.
- OpenAI-compatible endpoints.
- Presets for DeepSeek, Kimi/Moonshot, Qwen, MiniMax, GLM, SiliconFlow, and other compatible services.
- Custom providers.

The normalized provider interface includes:

```text
generate()
stream()
tool_call()
count_tokens()
estimate_cost()
capability_check()
```

Required behaviors:

- Per-agent provider and model selection.
- Provider capability detection.
- Structured JSON fallback when native tool calling is unavailable.
- Timeouts, retries, rate limits, and failover.
- Flow-level token and cost budgets.
- Local-only Ollama mode.
- Project policy that can prohibit external cloud providers.
- Redaction before sending protected values to remote providers.

Failover must not cause a previously submitted target-facing action to execute twice.

## 9. Tools and plugins

### 9.1 Phase 1 structured tools

- `http_request`
- `http_batch`
- `http_replay`
- `traffic_list`
- `traffic_search`
- `traffic_view`
- `traffic_sitemap`
- `web_crawl`
- `dir_enumerate`
- `api_discover`
- `openapi_analyze`
- `graphql_analyze`
- `auth_differential`
- `browser_navigate`
- `browser_capture`
- `tech_fingerprint`
- `network_scan`
- `dns_resolve`
- `encode_decode`
- `evidence_search`
- `evidence_view`
- `source_extract`
- `restricted_shell`
- Isolated, capability-controlled Python execution

Each tool declares:

- Input and output JSON schemas.
- Fixed risk level or deterministic classifier.
- Network and target-mutation behavior.
- Required worker capabilities.
- Timeout and resource limits.
- Evidence serializer.
- Redaction rules.
- Scope validator.

### 9.2 Plugin contract

```python
class vuln-proof-clawTool:
    manifest: ToolManifest

    async def validate(self, action, scope): ...
    async def execute(self, context): ...
    async def collect_evidence(self, result): ...
```

The manifest includes name, version, author, license, permissions, risk metadata, capabilities, and input/output schemas.

Phase 1 supports locally installed trusted plugins. Signed third-party packages, a remote registry, and a marketplace are deferred.

### 9.3 Web/API playbooks

The initial curated playbooks are:

- Web reconnaissance.
- API discovery.
- Authentication and session testing.
- Authorization and IDOR.
- Injection testing.
- SSRF, XXE, and file handling.
- Business-logic testing.
- Evidence verification.
- Bug bounty reporting.
- Remediation guidance.

Playbooks are reference material. They do not grant capabilities or bypass policy.

## 10. Reports

Phase 1 outputs:

- Markdown.
- JSON.
- HTML.
- SARIF.
- Bug bounty submission format.
- Machine-readable Evidence Manifest.

Reports contain:

- An executive summary for risk and remediation prioritization.
- Technical evidence with reproduction steps, requests, responses, PoCs, evidence IDs, and hashes.

Export redaction covers authorization headers, cookies, API keys, session tokens, personal information, and user-configured sensitive fields.

PDF output is deferred to the Web UI phase and generated from the HTML representation.

## 11. VulnClaw Phase 1 comparison

vuln-proof-claw Phase 1 must reach VulnClaw's practical Web/API baseline while improving isolation, policy enforcement, evidence integrity, independent verification, and report formats.

| Capability | VulnClaw baseline | vuln-proof-claw Phase 1 target |
|---|---|---|
| Autonomous workflow | Model-led solve loop | Planner, Operator, Verifier |
| CLI | CLI, REPL, TUI | CLI first; REPL considered for v0.3 |
| Web UI | Available | Deferred to v0.4 |
| Deployment | Primarily one application container | Control plane, PostgreSQL, disposable workers |
| Providers | Multiple presets | Native families plus compatible presets |
| HTTP and batch probing | Available | Structured request, batch, evidence, replay |
| Traffic evidence | Raw traffic files and indexes | Persisted evidence records and hash chain |
| Reconnaissance | Directory, JS, nmap, auth checks | Equivalent Web/API structured tools |
| Browser | External Chrome MCP | Isolated Playwright; MCP optional |
| Shell and Python | Built-in experimental capabilities | Isolated and capability-controlled |
| Skills | Broad security and CTF collection | Curated Phase 1 Web/API playbooks |
| Anti-hallucination | Evidence completion gate | Independent Verifier and finding lifecycle |
| Scope | Host/path/port and action checks | Scope-aware execution network boundary |
| Approval | Task constraints | L0-L4 action-bound approvals |
| Reporting | Markdown and PoC | Markdown, JSON, HTML, SARIF, bug bounty |

Phase 1 deliberately defers VulnClaw breadth that is outside the selected Web/API focus, including TUI, internal-network knowledge packs, Android/reversing content, and very long persistent loops.

## 12. Action reliability and error handling

### 12.1 Action states

```text
proposed
    ↓
policy_check
    ├── denied
    ├── pending_approval
    └── queued
          ↓
       running
          ├── succeeded
          ├── failed
          ├── timed_out
          ├── cancelled
          └── worker_lost
```

### 12.2 Reliability rules

- Every Action has an idempotency key.
- Read-only L0/L1 actions may retry according to policy.
- L2-L4 actions do not automatically retry.
- LLM failover cannot duplicate a target-facing action.
- Worker failures preserve available stdout, stderr, traffic, and evidence.
- Reports reference persisted evidence only.
- Flows have time, step, token, cost, request, and failure budgets.
- Users can pause, resume, and cancel flows.
- Denials, approvals, retries, cancellations, and policy decisions are audited.

## 13. Testing strategy

### 13.1 Unit tests

- Scope normalization.
- L0-L4 classification.
- Approval binding and replay prevention.
- Evidence hash-chain validation.
- Finding lifecycle.
- Redaction.

### 13.2 Contract tests

- LLM provider adapters.
- Tool and plugin schemas.
- Worker protocol.
- Report serializers.

### 13.3 Integration tests

- PostgreSQL migrations.
- Worker creation and destruction.
- API-to-Action-to-Evidence workflow.
- Timeout, cancellation, and worker-crash recovery.

### 13.4 Security tests

- Redirect scope escape.
- DNS rebinding.
- IPv4 and IPv6 normalization bypasses.
- Prompt injection from target content.
- Shell argument injection.
- Path traversal.
- Secret redaction.
- Approval replay and parameter mutation.

### 13.5 End-to-end lab tests

Active tests run only in an isolated CI network against intentionally vulnerable local targets such as:

- OWASP Juice Shop.
- crAPI.
- WebGoat.
- Purpose-built minimal test services.

No CI job performs active testing against public websites.

### 13.6 CI quality gates

- Ruff.
- mypy or Pyright.
- pytest and coverage.
- pip-audit.
- Bandit.
- CodeQL.
- Trivy.
- Secret scanning.
- Docker image builds.
- SBOM generation.

## 14. Open-source governance

The repository will include:

- `README.md`
- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `GOVERNANCE.md`
- `CHANGELOG.md`
- `ROADMAP.md`
- `THREAT_MODEL.md`
- `ARCHITECTURE.md`
- Issue and pull-request templates.
- Dependabot configuration.
- Release automation.
- Developer Certificate of Origin policy.
- Third-party notices.

The project uses the MIT License. VulnClaw and PentAGI will be acknowledged as inspirations. Reused code requires its original notices.

## 15. Delivery milestones

### Phase 0 — Foundation

- Repository and module structure.
- Docker Compose.
- FastAPI, CLI, and PostgreSQL.
- Migrations, configuration, and structured logging.
- CI and open-source governance files.

### v0.1 — Evidence Core

- Project, Engagement, and Scope.
- Worker lifecycle.
- HTTP request and response tooling.
- Action state machine.
- Evidence hash chain.
- Initial Markdown and JSON reports.

### v0.2 — Autonomous Core

- Planner, Operator, and Verifier.
- Multi-provider registry.
- Approval workflow.
- Execution context and evidence memory.
- Flow budgets and stopping conditions.

### v0.3 — Web/API Parity

- Crawler and directory enumeration.
- JavaScript, OpenAPI, and GraphQL discovery.
- Authentication differential testing.
- Browser and basic nmap integration.
- Restricted shell and Python.
- Web/API playbooks.
- HTML, SARIF, and bug bounty reports.

At v0.3, vuln-proof-claw must meet the selected VulnClaw Web/API baseline and demonstrate improvements in isolation, policy enforcement, evidence integrity, verification, and reporting.

### v0.4 — Web Experience

- React and TypeScript UI.
- Live flow view.
- Approval inbox.
- Evidence viewer.
- Finding review.
- Report preview.

### v1.0 — Stable Open-Source Release

- Stable REST API.
- Tool Plugin SDK.
- Upgrade and migration documentation.
- Security review.
- Performance and recovery testing.
- Published images, SBOMs, and signatures.

## 16. Phase 1 acceptance criteria

Phase 1 is complete when:

1. A user can start vuln-proof-claw with Docker Compose and operate it through the CLI.
2. An engagement cannot begin without an explicit scope.
3. Target-facing actions run in disposable workers.
4. Out-of-scope DNS, redirect, browser, and HTTP traffic is blocked at execution time.
5. L2-L4 actions cannot execute without the required approval state.
6. An approval cannot be reused after protected action parameters change.
7. Every tool result produces a verifiable evidence record.
8. Only the Verifier can promote a candidate finding.
9. A verified finding can be reproduced from stored evidence or replay definitions.
10. Reports can be exported without overwriting raw evidence.
11. The selected multi-provider families pass contract tests.
12. Active end-to-end tests run only against isolated local targets.
13. The v0.3 Web/API capability set reaches the documented VulnClaw comparison baseline.

## 17. Explicit non-goals

- Facilitating unauthorized testing.
- Treating prompts as a security boundary.
- Claiming forensic non-repudiation in Phase 1.
- Building a microservice platform before measured scaling needs exist.
- Maximizing agent count as a product feature.
- Allowing untrusted target content to grant capabilities.
- Automatically retrying high-risk actions.
