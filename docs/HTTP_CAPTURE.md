# Controlled HTTP capture contract

[繁體中文](HTTP_CAPTURE.zh-TW.md) | **English**

The capture coordinator is an internal orchestration boundary. It accepts only an
existing queued Action whose protected parameter digest matches the exact request.
Version 0.0.11 exposes this boundary through the opt-in passive assessment API.

## Enforced invariants

- Only `GET` and `HEAD` are accepted by the coordinator; the public passive API uses
  `GET` only.
- Targets are canonicalized, query strings and fragments are removed, and the result
  must be allowed by the persisted Engagement scope.
- Request headers are limited to `Accept` and `User-Agent`; credentials and cookies
  are rejected.
- Redirects and final-target changes are rejected.
- Timeouts are limited to 1–60 seconds.
- Response bodies are limited to 10 MiB, with a 1 MiB default.
- `HEAD` responses containing a body are rejected.
- Success stores a canonical request/response envelope in the persistent evidence
  chain.
- Transport failures produce a committed `failed` Action with a stable safe error
  code recorded in the audit trail.

## Network boundary

The opt-in `pinned-http/v1` transport is proxy-free and resolves every hostname
before connecting. It validates all DNS answers, rejects denied and unexpected
non-public addresses, pins the chosen IP to the socket, preserves HTTPS certificate
and SNI checks against the original hostname, disables redirects, and bounds bytes
while reading.

This transport is a deliberately narrow passive-preview adapter. It is not the
future disposable Worker runtime for crawlers, browsers, third-party scanners, or
active probes. Those capabilities still require container isolation, resource and
egress controls, cleanup, and independent execution lifecycle monitoring.
