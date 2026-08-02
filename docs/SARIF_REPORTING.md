# SARIF reporting

v0.4.0 exposes the current engagement report as SARIF 2.1.0 for code-scanning and
security-reporting workflows. It contains metadata and finding locations only; raw
HTTP bodies are never embedded.

## Direct report

```http
GET /api/v1/engagements/{engagement_id}/report.sarif
```

The response uses `application/sarif+json` and includes a `proofclaw_*` property set
for each result: review status, confidence, finding ID, evidence IDs, remediation,
and the finding record version. Severity maps to SARIF levels as follows:

| ProofClaw severity | SARIF level |
| --- | --- |
| critical, high | error |
| medium | warning |
| low, informational | note |

Rejected findings remain visible for auditability and carry a SARIF suppression with
the reason `Rejected during review`.

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
credential is required to download the stored bytes, and the API verifies the SHA-256
digest before returning them.

SARIF export is an interchange/reporting feature, not permission to run a scanner. The
existing Scope, DNS, Evidence, and budget controls remain the only target-facing path.
