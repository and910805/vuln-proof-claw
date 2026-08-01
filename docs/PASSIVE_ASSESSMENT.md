# Passive URL assessment preview

[繁體中文](PASSIVE_ASSESSMENT.zh-TW.md) | **English**

Version 0.0.11 is the first end-to-end target-facing MVP slice. Given an already
authorized Engagement and URL, it creates a low-risk Action, performs one bounded
GET request, stores tamper-evident Evidence, derives conservative Findings, and
returns links to the existing JSON and Markdown reports.

This is not an autonomous penetration-testing engine. It does not crawl, submit
forms, authenticate to targets, follow redirects, send payloads, or invoke external
security tools.

## Enablement

Target traffic is disabled by default:

```text
VULN_PROOF_CLAW_ASSESSMENT__ENABLED=true
VULN_PROOF_CLAW_ASSESSMENT__TIMEOUT_SECONDS=10
VULN_PROOF_CLAW_ASSESSMENT__MAX_RESPONSE_BYTES=1048576
VULN_PROOF_CLAW_ASSESSMENT__USER_AGENT=vuln-proof-claw/0.0.12
```

For Docker Compose development, copy `.env.example` to `.env`, change
`VULN_PROOF_CLAW_ASSESSMENT__ENABLED` to `true`, and recreate the API service.
Compose passes the four bounded assessment settings into the container. Keep the
service bound to loopback unless production authentication has been configured.

Production mode rejects this setting unless API authentication is also ready. Only
the operator role can start an assessment. The URL must already match the persisted
Engagement hostname/CIDR, scheme, port, path, and time window.

## Web console

Open `/#assessments`, select a Project, enter a hostname-based HTTP(S) URL, confirm
that you are authorized to assess the exact target, and start the assessment. The
wizard creates a 24-hour L0 Engagement limited to that hostname, scheme, port, and
path. It then shows the terminal Action state and Evidence/Finding counts and can
download the current JSON or Markdown engagement report.

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

{"target":"https://app.example.test/"}
```

The response contains the Action state, Evidence and Finding IDs, and report URLs.
Repeating the same key and protected target returns the stored result without another
network request. Reusing the key for another target returns
`409 idempotency_key_conflict`. Persisted status is available at:

```http
GET /api/v1/engagements/{engagement_id}/assessments/{action_id}
```

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
Each Finding references the captured Evidence. These checks are intentionally
conservative and are not a substitute for manual verification.

## Remaining path to autonomous assessment

The next milestones are a container-isolated runtime, orphan cleanup, bounded crawl
and endpoint discovery, OpenAPI analysis, an independent verifier, authenticated
browser sessions, and richer severity/remediation report contracts. Active probes
and exploit validation require separate approval and safety designs.
