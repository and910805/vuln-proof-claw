# Safe Automation Core

[繁體中文](SAFE_AUTOMATION.zh-TW.md) | **English**

Version 0.5.0 introduces the first API/MCP-first Planner/Operator/Verifier workflow.
It is deliberately bounded: it creates reviewed actions and independent comparison
results while existing engagement scope, risk policy, Approval, Worker, and evidence
controls remain authoritative.

## Browser and login isolation

`IsolatedBrowserRunner` creates a new headless Chromium process and Browser Context for
one run. Login selectors and `SecretStr` credentials are supplied in memory. Downloads
and Service Workers are disabled, requests outside the explicit host set are aborted,
and the Context and process are closed in `finally`. Results contain the final URL,
title, status, screenshot bytes, and blocked request URLs—never credentials or storage
state.

Install the optional local runtime with:

```bash
python -m pip install --editable ".[browser]"
python -m playwright install chromium
```

The isolated Worker image installs Chromium with its operating-system dependencies.

## Reviewed mutation plans

`MutationPlan` supports query, a small reviewed header allowlist, and exact path-value
replacement. Plans require a reviewer identity and reason, contain no more than eight
mutations, and produce a canonical SHA-256 digest. Built-in strategies are empty value,
integer boundary, type mismatch, and a benign validation marker. Authorization, Cookie,
Host, forwarding, and other sensitive headers are not mutable.

Input-validation automation rejects plans without reviewed mutations. A changed plan
produces a different digest and therefore cannot reuse an exact Approval.

## Security comparisons

- CORS detects credentialed wildcard origins and credentialed origin reflection without
  `Vary: Origin`.
- Authentication compares anonymous and authenticated observations.
- Authorization compares lower- and higher-privilege observations.
- Input validation compares a baseline with a reviewed benign mutation and flags a newly
  introduced server error.

Results are `pass`, `candidate`, or `inconclusive`. A candidate is not automatically a
verified Finding; the evidence and affected authorization assumptions still require the
Verifier or manual review path.

## Approval Presets

An authenticated approver creates an engagement-scoped Preset with allowed action types,
target prefixes, maximum risk, and Approval TTL. An operator may apply it only to a
matching `pending_approval` Action. Every application creates a new exact Approval bound
to the Action type, normalized target, parameter digest, risk, expiration, and a single
execution. Presets never widen engagement scope.

## Planner / Operator / Verifier API

`POST /api/v1/engagements/{id}/automation-plans` creates one Flow, one Task per selected
check, policy-evaluated Actions, a mutation digest where applicable, and an immutable
`automation.plan_created` audit event. `POST /api/v1/automation/verify` performs the
independent deterministic comparison. Target execution still goes through the existing
Action/Approval/Worker path.

This release does not add destructive payloads, unrestricted scanning, arbitrary browser
scripts, cross-scope login, automatic privilege escalation, or automatic verification of
candidate Findings.
