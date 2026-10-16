# SARIF reporting

v0.4.0 exposes the current engagement report as SARIF 2.1.0 for code-scanning and
security-reporting workflows. It contains metadata and finding locations only; raw
HTTP bodies are never embedded.

## Direct report

```http
GET /api/v1/engagements/{engagement_id}/report.sarif
```

The response uses `application/sarif+json` and includes only `verified` findings as
results. Each result has a `proofclaw_*` property set: review status, confidence,
finding ID, evidence IDs, remediation, and the finding record version. Candidate,
pending, manual-review, and rejected findings remain visible in the JSON, Markdown,
and HTML engagement reports. Severity maps to SARIF levels as follows:

| ProofClaw severity | SARIF level |
| --- | --- |
| critical, high | error |
| medium | warning |
| low, informational | note |

If a verified finding's linked evidence is missing, belongs to another engagement,
or fails integrity checks, the report request fails instead of exporting that claim.

## Immutable export

Operators can create a stored snapshot with the report export contract:

```http
POST /api/v1/engagements/{engagement_id}/report-exports
Authorization: Bearer <operator token>
Idempotency-Key: sarif-<engagement>-<revision>
Content-Type: application/json

{"format":"sarif"}
```

The resulting digest, size, and media type are persisted. A dedicated evidence-reader
credential is required to download the stored bytes. Before download or an
idempotency-key replay, the API verifies the SHA-256 digest and rechecks any verified
claims against their current Finding state and linked evidence. A historical export
whose verified claim was later rejected or whose evidence became invalid is refused.

SARIF export is an interchange/reporting feature, not permission to run a scanner. The
existing Scope, DNS, Evidence, and budget controls remain the only target-facing path.
