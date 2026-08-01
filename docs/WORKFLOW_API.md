# Control-plane workflow API

[繁體中文](WORKFLOW_API.zh-TW.md) | **English**

Version 0.0.6 connects the persisted `Engagement -> Flow -> Task -> Action` model to
the v1 REST API. An HTTP action proposal is normalized, classified, checked against
the engagement scope, transitioned to a durable state, and recorded in the audit
trail in one database transaction.

This API does **not** send target-facing traffic. An automatically allowed action is
only moved to `queued`. Concrete execution stays disabled until a disposable worker
can enforce DNS pinning, egress scope, resource limits, and evidence return.

## Lifecycle

1. Create a flow under an existing scoped engagement.
2. Create a task under that flow.
3. Propose a bounded `GET` or `HEAD` HTTP action with an idempotency key.
4. The server normalizes the target and action type, computes the protected parameter
   digest, classifies risk, and evaluates policy.
5. The action is persisted as `queued`, `pending_approval`, or `denied`.
6. `action.proposed` and `policy.decision` audit records preserve the decision path.

The proposal endpoint accepts only the request headers supported by the capture
contract: `Accept` and `User-Agent`. Authentication, cookie, redirect, body, and
arbitrary-method inputs are rejected before an Action is stored.

## Endpoints

| Method and path | Purpose |
| --- | --- |
| `POST /api/v1/engagements/{id}/flows` | Create a testing objective |
| `GET /api/v1/engagements/{id}/flows` | List flows with pagination |
| `POST /api/v1/flows/{id}/tasks` | Create a planned unit of work |
| `GET /api/v1/flows/{id}/tasks` | List tasks with pagination |
| `POST /api/v1/tasks/{id}/http-actions` | Propose and policy-check an HTTP capture |
| `GET /api/v1/engagements/{id}/actions` | List persisted action states |
| `GET /api/v1/actions/{id}` | Read one persisted action |
| `GET /api/v1/engagements/{id}/audit-events` | Inspect immutable audit events |

Exact retries with the same engagement-scoped idempotency key return the existing
Action with HTTP 200. Reusing that key with a different task, target, action type,
risk, or protected request digest returns HTTP 409.

## Security boundary

- Scope and engagement policy are loaded from persistence; clients cannot supply a
  policy result or risk level.
- Unknown action types conservatively classify as L2.
- Permanent-deny action types and out-of-scope targets are persisted as denied.
- L2-L4 and default L1 proposals stop at `pending_approval`; an authenticated,
  separately configured approver may grant or deny the exact Action.
- Audit payloads contain identifiers, normalized targets, digests, and decisions,
  but not request header values or raw evidence.
- Local mode records `api:unauthenticated`. Authentication-ready deployments require
  Bearer credentials and record configured operator and approver identities.

See [Controlled HTTP capture](HTTP_CAPTURE.md) for the separate internal execution
contract and [Evidence Core preview](EVIDENCE_CORE.md) for report integrity behavior.
See [Authentication and single-action approvals](AUTH_AND_APPROVALS.md) for role and
deployment requirements.
