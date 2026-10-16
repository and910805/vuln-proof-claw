# Finding review

[繁體中文](FINDING_REVIEW.zh-TW.md) | **English**

The review endpoint lets an operator decide whether a candidate's existing evidence
supports a verified claim. It changes only control-plane state; it never sends a new
request to the target. Some deterministic observed checks also create `verified`
findings directly, without using this endpoint. See the broader
[finding validation model](FINDING_VALIDATION.md).

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
  "verification_method": "observed",
  "comment": "The captured response directly shows the claimed missing header."
}
```

A candidate may use this request to state its `verification_method` as `observed` or
`differential`. A differential review may also attach `control_evidence_ids` captured
through separately authorized Actions. These fields describe existing evidence; they
do not perform a retest.

The response includes the new `version`, the evidence IDs bound to the finding, and
the reviewer identity. Clients must send the version they read. A stale version
returns `409 finding_version_conflict`, so two operators cannot silently overwrite
one another's decision.

## Status rules

- `pending_verification`: explicitly queued for review.
- `verified`: an explicit operator assertion that the current evidence supports the
  precise claim. It requires at least one payload evidence record, a stated
  `observed` or `differential` method, and a non-empty reviewer rationale. A
  `differential` claim also requires separate control evidence.
- `rejected`: the current evidence does not support the claim.
- `needs_manual_review`: the automated result needs a human decision or more context.

Before accepting `verified`, the API verifies the full engagement evidence chain and
checks that each linked payload or control record exists and belongs to the finding's
engagement. Missing, cross-engagement, or integrity-invalid evidence blocks promotion.
For a `differential` finding, the gate also rejects a test and control capture with
identical raw bytes (`finding_control_not_distinct`). Different bytes are only a
sanity check; they do not establish that the correct variable changed or that the
observed difference proves the claim.
Reports expose the test and control evidence IDs separately, so a reader can tell
which captured exchange supports the claim and which acts as the comparison.
The reviewer rationale is stored in the immutable `finding.reviewed` audit event,
not in the finding title or target data. Other successful review decisions also create
that event; their comment remains optional. The endpoint requires the operator role
when API authentication is enabled.

This gate checks evidence provenance and integrity, not the semantic truth of a
vulnerability. It does not yet prove that the owning Action succeeded, that an
Action's target matches the Finding's target, or that a response demonstrates the
claimed security impact. Those checks need a typed, evidence-derived Verifier and
target-aware retest; the operator must assess the claim and its alternative
explanations before marking it verified.

## Safety boundary

Reviewing a finding does not authorize a new target-facing action, widen scope, or
change the action policy. A verified status is a reporting assertion, not proof of
exploitability. Any retest must have its own scoped, policy-checked Action and
Approval where required.
