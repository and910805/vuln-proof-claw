# Authenticated Engine gateway boundary

[繁體中文](ENGINE_GATEWAY.zh-TW.md) | **English**

Version 0.0.18 implements both sides of a narrow HTTP boundary between the control
plane and a separately operated privileged Engine process. The API process neither
mounts an Engine socket nor invokes a container CLI.

## Trust boundary

The client accepts HTTPS origins, or explicit loopback IP literals for local
development. URLs cannot contain credentials, paths, queries, or fragments. Redirects
and ambient proxy discovery are disabled. Both processes require the same 32–4096
character Bearer secret, which must be distinct from every API role token.

The server is disabled by default and refuses construction without an explicit enable
flag and token. Its OpenAPI and interactive documentation endpoints are disabled.
Version 0.0.18 can inject the separately enabled fixed-field Docker adapter; without
that explicit backend policy, readiness deliberately returns a safe availability code.

## Versioned lifecycle contract

Every operation uses authenticated JSON over `/v1`:

- `POST /v1/health/ready`
- `POST /v1/containers/create`
- `POST /v1/containers/start`
- `POST /v1/containers/wait`
- `POST /v1/containers/stop`
- `POST /v1/containers/remove`
- `POST /v1/containers/inventory`

References remain opaque JSON values rather than URL path components. Create requests
independently revalidate the digest-pinned image, Worker/name/request identity,
non-root user, fixed privilege restrictions, resource ceilings, tmpfs policy,
ownership labels, and strict Worker protocol payload.

## Server controls

Authentication runs before request parsing or backend admission. Declared
`Content-Length` and actual streamed bytes are capped before strict JSON validation;
unknown fields are rejected. A semaphore bounds concurrent privileged operations, and
queue admission has a short timeout. Worker output is checked again before encoding.

Expected backend states map to stable codes for busy, conflict, not found, rejected,
and unavailable conditions. Unexpected exception text, daemon paths, credentials, and
response bodies never cross the boundary. No mutating operation is blindly retried.

The listener can be launched separately with:

```console
vuln-proof-claw-engine
```

Required environment settings are documented in `.env.example`. Keep both the server
and Docker backend disabled until the Engine process is isolated and its exact image
digest and internal network are configured. See
[DOCKER_ENGINE_BACKEND.md](DOCKER_ENGINE_BACKEND.md).

## Current boundary

The client, server, shared schemas, authentication, request and response bounds,
admission control, safe error mapping, configuration gates, and in-memory end-to-end
contract and fixed-field Unix-socket Docker adapter are complete and tested without
daemon access. Scoped egress, Worker-side executor capability, published Worker image
digests, control-plane startup integration, and an isolated live target fixture remain
for subsequent releases. Consequently the Compose runtime remains disabled.
