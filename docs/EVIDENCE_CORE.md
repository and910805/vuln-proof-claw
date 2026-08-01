# Evidence Core preview

[繁體中文](EVIDENCE_CORE.zh-TW.md) | **English**

The v0.1 preview connects persisted, normalized engagement scope to the control-plane API. It deliberately does not enable target-facing execution.

## Available

- Create and list time-bounded engagements beneath an existing project.
- Store one normalized allow/deny scope policy with each engagement.
- Evaluate a candidate URL against the persisted scope without contacting the target.
- Generate metadata-only JSON and Markdown engagement reports.
- Upgrade existing databases with Alembic revision `0002_engagement_scopes`.

## API

- `POST /api/v1/projects/{project_id}/engagements`
- `GET /api/v1/projects/{project_id}/engagements`
- `GET /api/v1/engagements/{engagement_id}`
- `POST /api/v1/engagements/{engagement_id}/scope/evaluate`
- `GET /api/v1/engagements/{engagement_id}/report`
- `GET /api/v1/engagements/{engagement_id}/report.md`

Scope creation requires at least one allowed hostname or CIDR. Hostnames, networks, ports, schemes, and paths are normalized before storage. A scope inherits its engagement time window by default and cannot expand beyond it. Deny rules take precedence and unknown targets fail closed.

## Safety boundary

Scope evaluation is a pure control-plane decision. It does not resolve DNS, send an HTTP request, follow redirects, or create a worker. A hostname result is marked `requires_dns_recheck`; a future execution adapter must re-resolve and enforce the approved network boundary for every connection and redirect.

Raw evidence and canonical metadata can now be persisted transactionally and re-verified from stored bytes. Raw payloads remain internal and reports expose only their integrity status and safe metadata. The durable Worker lifecycle registry validates successful Evidence references and reconciles abandoned work after restart, while a concrete target-facing runtime, authenticated evidence access, and report export artifacts remain v0.1 implementation gates.
