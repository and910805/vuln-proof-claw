# Security Policy

[繁體中文](SECURITY.zh-TW.md) | **English**

## Supported versions

vuln-proof-claw is pre-alpha software. Security fixes are applied to the latest commit on `mainer` until the first versioned release.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities that could expose credentials, escape a worker, bypass scope or approval policy, execute unintended commands, alter evidence, or affect other users.

Use GitHub private vulnerability reporting for this repository. Include:

- A concise description and affected revision.
- Reproduction steps or a minimal test case.
- Expected and observed behavior.
- Security impact and required preconditions.
- Any suggested remediation.

Do not include real customer data, live credentials, or results obtained from systems you were not authorized to test.

## Response targets

- Initial acknowledgement: within 5 business days.
- Triage decision: within 10 business days.
- Remediation timeline: communicated after severity and exploitability are confirmed.

These are targets, not service-level guarantees.

## Safe research

Research must use systems you own or are explicitly authorized to test. Avoid privacy violations, persistence, destructive actions, and unnecessary data access. Stop testing when continued activity could harm users or infrastructure.
