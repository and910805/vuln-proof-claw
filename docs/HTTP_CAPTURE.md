# Controlled HTTP capture contract

[繁體中文](HTTP_CAPTURE.zh-TW.md) | **English**

The v0.1 capture coordinator is an internal orchestration boundary, not a public scanning endpoint. It accepts only an existing queued Action whose protected parameter digest matches the exact request.

## Enforced invariants

- Only `GET` and `HEAD` are accepted.
- Targets must already be canonical and allowed by the persisted Engagement scope.
- Request headers are limited to `Accept` and `User-Agent`; credentials and cookies are rejected.
- Redirects and final-target changes are rejected.
- Timeout is limited to 1–60 seconds.
- Response bodies are limited to 10 MiB, with a 1 MiB default.
- `HEAD` responses containing a body are rejected.
- Success stores a canonical request/response envelope in the persistent evidence chain.
- Transport failures produce a committed `failed` Action result with a safe error code.

## Network boundary

No concrete network transport is enabled in this release. The coordinator receives an injected transport implementing the internal contract. A production transport must run inside the disposable Worker boundary, disable redirects, pin DNS results, enforce CIDR/port/scheme/path scope for every connection, and bound bytes while streaming rather than after buffering.

This separation is intentional: a generic HTTP client in the control plane cannot safely enforce DNS rebinding and redirect scope by itself.
