# Evidence access and report exports

[繁體中文](EVIDENCE_ACCESS_AND_REPORT_EXPORTS.zh-TW.md) | **English**

Version 0.0.10 completes a guarded review loop for persisted evidence and engagement
reports. This capability does not run scanners or contact assessment targets.

## Roles and readiness

Set API authentication as documented in [Authentication and single-action
approvals](AUTH_AND_APPROVALS.md), then add a third secret:

```text
VULN_PROOF_CLAW_API__EVIDENCE_READER_IDENTITY=evidence-reader@example.test
VULN_PROOF_CLAW_API__EVIDENCE_READER_TOKEN=<a third random secret of at least 32 characters>
```

All configured tokens must be distinct. Existing authenticated deployments may omit
the evidence-reader token, but sensitive download endpoints then return
`503 evidence_access_not_ready`. The role boundary is deliberate:

- an operator creates report snapshots;
- an evidence reader downloads report content and raw evidence;
- an approver cannot perform either operation;
- successful sensitive reads record the configured reader identity in the audit trail.

## Immutable report workflow

Create a snapshot with an operator token and a required idempotency key:

```http
POST /api/v1/engagements/{engagement_id}/report-exports
Authorization: Bearer <operator token>
Idempotency-Key: final-report-2026-08-01
Content-Type: application/json

{"format":"json"}
```

`format` accepts `json`, `markdown`, or `sarif`. Repeating the same key and format returns the
original snapshot. Reusing the key for another format returns
`409 idempotency_key_conflict`. List metadata at `GET .../report-exports`; content is
not included in that response.

Download content with the evidence-reader token from
`GET .../report-exports/{export_id}/download`. Before returning bytes, the API
recomputes the stored size and SHA-256 digest. A mismatch returns
`409 report_export_integrity_failed`. Successful responses include `ETag`,
`X-Content-SHA256`, `Content-Disposition`, and `Cache-Control: no-store` headers.

## Raw evidence workflow

Use the evidence ID exposed by the metadata-only engagement report:

```http
GET /api/v1/engagements/{engagement_id}/evidence/{evidence_id}/raw
Authorization: Bearer <evidence-reader token>
```

The API verifies the full engagement evidence chain before release and checks that
the evidence belongs to the path's engagement. Invalid chains return
`409 evidence_integrity_failed`; cross-engagement and unknown IDs return the same
`404 evidence_not_found` boundary. Responses include the raw-content SHA-256 in
`X-Content-SHA256` and the canonical evidence-chain digest in `X-Evidence-Digest`.

## Current limitations

Report snapshots and evidence payloads currently reside in the control-plane
database. External encrypted object storage, retention policy, reader token rotation,
per-project RBAC, browser sessions, and an evidence viewer require later designs.
