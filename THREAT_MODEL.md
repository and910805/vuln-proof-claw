# Threat Model

[繁體中文](THREAT_MODEL.zh-TW.md) | **English**

## Scope

Phase 0 covers the control-plane foundation and worker protocol. It does not execute scans, LLM actions, arbitrary shell commands, or browser automation.

## Protected assets

- Provider and database credentials.
- Engagement scope and approval records.
- Raw evidence, hashes, reports, and audit events.
- Host filesystem, Docker daemon, worker images, and project data.

## Trust boundaries

- User/CLI to API.
- API to PostgreSQL.
- Control plane to Worker Manager.
- Worker Manager to disposable workers.
- Future workers to authorized targets.
- Future control plane to external or local LLM providers.

## Primary threats

- Scope bypass through DNS, redirects, IPv4/IPv6 ambiguity, proxies, or browser subresources.
- Approval replay or parameter mutation.
- Operator/approver token theft, role confusion, or credentials leaked through URLs and logs.
- Prompt injection from target-controlled data.
- Worker escape, unsafe mounts, Docker-socket abuse, or credential leakage.
- Command/path injection and malicious plugins.
- Evidence deletion, reordering, replacement, or report misrepresentation.
- Cross-project data leakage and denial of service.

## Required controls

- Code-enforced scope checks at execution time.
- L0-L4 risk policy and action-bound approvals.
- Distinct constant-time checked Bearer credentials for operator and approver duties.
- Disposable non-root workers with resource and network limits.
- Secret redaction and no provider credentials in workers.
- Canonical evidence hashing and append-oriented audit records.
- Project isolation, bounded retries, idempotency, and fail-closed errors.

## Non-goals

Phase 0 does not claim forensic non-repudiation, hostile multi-tenant isolation, or safe execution of untrusted third-party plugins.
