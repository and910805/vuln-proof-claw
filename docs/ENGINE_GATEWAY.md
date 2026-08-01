# Authenticated Engine gateway client

[繁體中文](ENGINE_GATEWAY.zh-TW.md) | **English**

Version 0.0.16 implements the control-plane client and strict wire contract for a
future privileged Engine gateway. It connects the restricted container policy to a
narrow authenticated HTTP boundary without mounting the Docker socket or invoking
the Docker CLI from the API process.

## Connection policy

The gateway origin and token must be configured together. HTTPS is required except
for explicit loopback IP literals such as `127.0.0.1` or `::1`; `localhost` over
unencrypted HTTP is rejected to avoid host-file and DNS ambiguity. Gateway URLs cannot
contain credentials, paths, queries, or fragments. A private CA bundle is optional.

The Bearer token must contain 32–4096 visible ASCII characters, must be distinct from API operator,
approver, and evidence-reader tokens, and remains a `SecretStr`. Redirect following
and environment proxy discovery are disabled, so credentials cannot be forwarded to
another origin or an ambient proxy.

## API contract

Every operation uses authenticated JSON over the versioned `/v1` boundary:

- `POST /v1/health/ready`
- `POST /v1/containers/create`
- `POST /v1/containers/start`
- `POST /v1/containers/wait`
- `POST /v1/containers/stop`
- `POST /v1/containers/remove`
- `POST /v1/containers/inventory`

Container references remain opaque JSON values and never enter URL paths. Create
requests revalidate the digest-pinned image, Worker UUID, non-root user, positive hard
resource ceilings, fixed `cap_drop=ALL`, read-only root, `no-new-privileges`, required
tmpfs paths/options, complete ownership labels, and the strict `WorkerRequest` payload.
The Worker ID, request ID, container name, labels, and protocol payload must agree.

## Bounded responses

Responses are streamed into a bounded buffer. Both declared `Content-Length` and
actual streamed bytes are checked, content type must be JSON, unknown response fields
are rejected, and base64 Worker output is checked again after decoding. HTTP and
transport details become stable safe codes such as:

- `engine_gateway_unauthorized`
- `engine_gateway_conflict`
- `engine_gateway_request_rejected`
- `engine_gateway_response_limit_exceeded`
- `engine_gateway_response_invalid`
- `engine_gateway_unavailable`

No operation is automatically retried because create/remove ambiguity must be
resolved using the immutable ownership inventory rather than blind replay.

## Current boundary

The client, configuration gate, readiness contract, wire schemas, bounded transport,
and integration with `DockerWorkerRuntime` are complete and tested. The separate
gateway server that owns Engine credentials, scoped egress enforcement, Worker-side
executor, application startup wiring, and isolated target fixture remain pending.
Consequently `RUNTIME_ENABLED` stays false in Compose and no new target-facing tool
execution is enabled in this release.
