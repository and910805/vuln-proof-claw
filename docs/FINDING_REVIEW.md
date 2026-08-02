# Finding review

v0.4.0 adds a small, explicit review step between automated candidate detection and
reporting a finding as verified. The review endpoint changes only the control-plane
state; it never sends a new request to the target.

## Endpoint

```http
PATCH /api/v1/engagements/{engagement_id}/findings/{finding_id}
Authorization: Bearer <operator token>
Content-Type: application/json
```

```json
{
  "status": "verified",
  "expected_version": 1,
  "comment": "Evidence reviewed by the operator."
}
```

The response includes the new `version`, the evidence IDs bound to the finding, and
the reviewer identity. Clients must send the version they read. A stale version
returns `409 finding_version_conflict`, so two operators cannot silently overwrite
one another's decision.

## Status rules

- `pending_verification`: explicitly queued for review.
- `verified`: evidence-backed and ready for a verified report result. At least one
  evidence record is required.
- `rejected`: the current evidence does not support the claim.
- `needs_manual_review`: the automated result needs a human decision or more context.

Every successful decision creates an immutable `finding.reviewed` audit event. The
optional comment is stored in that audit payload, not in the finding title or target
data. The endpoint requires the operator role when API authentication is enabled.

## Safety boundary

Reviewing a finding does not authorize a new target-facing action, widen scope, or
change the action policy. A verified status is a reporting assertion backed by the
existing evidence chain; active payloads and state-changing requests remain disabled.
