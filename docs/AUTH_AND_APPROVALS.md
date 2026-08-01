# Authentication and single-action approvals

[繁體中文](AUTH_AND_APPROVALS.zh-TW.md) | **English**

Version 0.0.7 adds a pre-alpha control-plane authentication boundary and a
separation-of-duty approval workflow. It is intentionally small: two deployment
credentials identify an operator and an approver, while health endpoints remain
public for orchestration probes.

## Modes

Authentication is disabled by default for loopback-only local development. In this
mode, existing project and workflow mutations remain available, but approval
mutations return `503 authentication_not_ready`. An unauthenticated process therefore
cannot grant authority for an L1-L4 Action.

When `VULN_PROOF_CLAW_API__AUTHENTICATION_READY=true`:

- all non-health `/api/v1` routes require a Bearer token;
- the operator token may create projects, engagements, flows, tasks, and Actions,
  and may cancel non-terminal Actions;
- the approver token may read control-plane state and approve or deny a
  `pending_approval` Action;
- the two tokens must be distinct and at least 32 characters;
- audit events use the configured operator or approver identity, never a client
  supplied identity.

Required settings:

```text
VULN_PROOF_CLAW_API__AUTHENTICATION_READY=true
VULN_PROOF_CLAW_API__OPERATOR_IDENTITY=operator@example.test
VULN_PROOF_CLAW_API__APPROVER_IDENTITY=security-lead@example.test
VULN_PROOF_CLAW_API__OPERATOR_TOKEN=<random secret of at least 32 characters>
VULN_PROOF_CLAW_API__APPROVER_TOKEN=<different random secret of at least 32 characters>
```

Send credentials only in the `Authorization: Bearer ...` header. Production use
also requires TLS at a trusted reverse proxy, secret-manager injection, access-log
redaction, and periodic token rotation. Tokens must never be placed in URLs,
committed configuration, captured evidence, or browser source code.

The bundled Web console does not yet implement a credential-entry session. With
authentication enabled, use an authenticated API client until the v0.4 session UI is
implemented.

Version 0.0.10 optionally adds a third, distinct evidence-reader identity and token.
When configured, this token can authenticate read-only API requests and is the only
role accepted by raw-evidence and immutable report-content download endpoints.
Operators create report exports but cannot download their content. See
[Evidence access and report exports](EVIDENCE_ACCESS_AND_REPORT_EXPORTS.md).

## Approval decision

`POST /api/v1/actions/{action_id}/approval-decision` accepts:

```json
{
  "decision": "approve",
  "reason": "Authorized validation",
  "expires_in_seconds": 900
}
```

Only an Action currently in `pending_approval` can be decided. Approval expiry is
limited to 60-3600 seconds and cannot exceed the Engagement window. Each approval is
single use and is bound to the exact Engagement, action type, normalized target,
parameter digest, and risk level.

An approval moves the Action to `queued` but is not consumed yet. The execution
coordinator rechecks the persisted Scope and Approval immediately before transport,
then atomically marks the Action `running` and consumes the single execution. An
expired, changed, missing, or already consumed Approval fails closed before target
traffic.

A denial transitions the Action directly to `denied`. The operator can use
`POST /api/v1/actions/{action_id}/cancel` for any supported non-terminal state.
Grant, denial, and cancellation records include actor, reason, identifiers, and
protected metadata in the immutable audit trail.

## Current boundary

This is a pragmatic pre-alpha Bearer-token boundary, not the final multi-user
identity system. It does not provide password login, token issuance, revocation,
federation, browser sessions, or per-project RBAC. Those require a separate schema
and migration plan before production deployment.
