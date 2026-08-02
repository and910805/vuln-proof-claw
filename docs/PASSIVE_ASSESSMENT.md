# Bounded Web and safe active assessment

[繁體中文](PASSIVE_ASSESSMENT.zh-TW.md) | **English**

Version 0.3.0 combines bounded, same-origin Web discovery with safe active API verification.
Given an authorized Engagement and URL, it captures the starting page, extracts
same-origin candidates, follows them within a selected hard budget, stores
tamper-evident Evidence per page, derives prioritized Findings, and returns JSON,
Markdown, and escaped HTML reports. In `active-safe` mode, captured OpenAPI documents
are parsed and eligible parameterless GET/HEAD operations are verified automatically.

This is not yet a complete autonomous penetration-testing engine. It does not submit
forms, authenticate to targets, follow redirects, execute documented write operations,
send exploit payloads, or invoke external security tools.

## Enablement

The application-level default remains disabled. The loopback-only local Docker
Compose profile enables this bounded path so the first-run experience works:

```text
VULN_PROOF_CLAW_ASSESSMENT__ENABLED=true
VULN_PROOF_CLAW_ASSESSMENT__TIMEOUT_SECONDS=10
VULN_PROOF_CLAW_ASSESSMENT__MAX_RESPONSE_BYTES=1048576
VULN_PROOF_CLAW_ASSESSMENT__USER_AGENT=vuln-proof-claw/0.3.1
```

Docker Compose passes the four bounded assessment settings into the container.
Set `VULN_PROOF_CLAW_ASSESSMENT__ENABLED=false` in `.env` to disable target traffic.
Keep the service bound to loopback unless production authentication is configured.

Production mode rejects this setting unless API authentication is also ready. Only
the operator role can start an assessment. The URL must already match the persisted
Engagement hostname/CIDR, scheme, port, path, and time window.

## Web console

Open `/#assessments`, enter a hostname-based HTTP(S) URL, acknowledge that you are
authorized, and start. The acknowledgement is remembered in that browser; it is not
an extra step on every run. The first run creates a private workspace automatically.
Project selection remains available under advanced organization options.

The wizard creates a 24-hour L0 Engagement limited to the normalized hostname,
scheme, port, and selected path prefix. These controls stay behind the interface.
Safe, Fast, and Deep presets cap discovery at 5, 15, and 30 requests/pages. The
result view shows severity, confidence, remediation, Evidence integrity, API operation
counts, safe active probes, and JSON, Markdown, or HTML reporting. Safe automation is
the default; discovery-only mode remains available as one explicit selection.

Authenticated deployments can enter the operator token through **Operator access**.
The credential is held only in tab-scoped `sessionStorage` and can be cleared from
the same dialog. IP literals and private targets are not auto-scoped by the wizard;
they require a separately reviewed Engagement created through the API.

## Request

```http
POST /api/v1/engagements/{engagement_id}/assessments
Authorization: Bearer <operator token>
Idempotency-Key: baseline-homepage-1
Content-Type: application/json

{"target":"https://app.example.test/","preset":"safe","mode":"active-safe"}
```

The active phase has a separate hard ceiling of ten operations and 45 seconds. Only
GET/HEAD operations without required parameters or templated paths are eligible. All
write methods and parameterized operations remain inventory-only.

The response contains the Action state, Evidence and Finding IDs, and report URLs.
Repeating the same key and protected target returns the stored result without another
network request. Reusing the key for another target returns
`409 idempotency_key_conflict`. Persisted status is available at:

```http
GET /api/v1/engagements/{engagement_id}/assessments/{action_id}
```

Persisted runs can also be listed newest first without producing target traffic:

```http
GET /api/v1/assessments?project_id={project_id}&limit=50&offset=0
```

The list returns normalized targets, terminal state and time, Evidence/Finding counts,
stable failure codes, and report links. Omitting `project_id` returns history across projects.

## Network controls

- The system resolver is queried before connecting and every answer is validated.
- Any mixed answer containing an unexpected private, loopback, link-local, reserved,
  or denied address rejects the whole request.
- A private address is accepted only when the Engagement explicitly allows its CIDR.
- The selected address is pinned for the socket connection; HTTPS certificate and
  SNI validation still use the original hostname.
- Environment proxy variables are not used.
- Redirects and final-target changes are rejected.
- Response bytes are bounded while reading, and an oversized declared
  `Content-Length` is rejected before the body is read.

## Findings

The deterministic analyzer currently evaluates cleartext HTTP, HSTS,
`X-Content-Type-Options`, HTML CSP and Referrer Policy, version-bearing Server
headers, and Secure/HttpOnly/SameSite flags on cookie names that look sensitive.
Each Finding references the captured Evidence and includes severity, confidence,
and remediation. These checks are intentionally conservative and are not a
substitute for manual verification.

## Remaining path to autonomous assessment

The next milestones are semantic OpenAPI analysis, an independent verifier,
authenticated browser sessions, and SARIF export. Active probes and exploit
validation require separate approval and safety designs. The optional AI interaction
layer is described in [AI Driver Architecture](AI_DRIVER.md).
