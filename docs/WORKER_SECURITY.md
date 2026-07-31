# Worker and container security

[繁體中文](WORKER_SECURITY.zh-TW.md) | **English**

This document defines the Phase 0 container trust boundaries. It is a security requirement, not a claim that container isolation alone is sufficient for hostile workloads.

## Current boundary

- The API and worker images run as dedicated non-root users.
- The Compose API service uses a read-only root filesystem, drops every Linux capability, enables `no-new-privileges`, and applies CPU, memory, PID, and temporary-storage limits.
- PostgreSQL is reachable only on the Compose control-plane network and is not published to the host.
- Only the API health endpoint is published, on `127.0.0.1:8080`.
- The worker image has no Docker socket, host home directory, credential-store, or control-plane provider credential mount.
- Compose reserves an internal-only `vuln-proof-claw-workers` network with no external egress.
- The Phase 0 `DisabledWorkerManager` fails closed and performs no target-facing execution.

The Compose defaults are for local development. The default database password is not suitable for shared or production environments.

## Docker socket threat

Access to the Docker socket is effectively host-level administrative access. A process with unrestricted socket access can create privileged containers, mount host paths, inspect environment variables, and escape the intended worker boundary.

Therefore:

1. Never mount `/var/run/docker.sock` into the API or worker container.
2. Never expose the Docker API over an unauthenticated TCP endpoint.
3. Treat a future Docker Worker Manager as a separate privileged security boundary.
4. Give that manager a narrow request schema and an allowlist of image, mount, network, resource, and lifecycle operations.
5. Reject host paths, the Docker socket, privileged mode, added capabilities, host networking, and unapproved images.
6. Audit every worker create, start, cancel, collect, and destroy operation.
7. Prefer a restricted socket proxy or a dedicated execution service over direct socket access.

## Worker invariants

Every concrete Worker Manager must enforce:

- An exact `v1` protocol schema with unknown fields rejected.
- A canonical target and a worker-local copy of the approved scope.
- A bound approval identifier for L2–L4 requests.
- Disposable per-action workers and task directories.
- Read-only root filesystems wherever the selected tool permits.
- Explicit CPU, memory, PID, and timeout limits.
- Network egress restricted to the approved target scope, including DNS, redirects, browser subresources, and proxies.
- No control-plane LLM credentials in worker requests or environments.
- Evidence collection before worker cleanup.
- Cleanup after success, failure, timeout, cancellation, or worker loss.

## Phase 0 limitations

Phase 0 defines the protocol and fail-closed manager interface only. It does not yet create containers or execute security tools. The internal-only worker network remains closed until scoped egress is implemented. Network-policy enforcement, a restricted runtime adapter, and isolated end-to-end targets are later implementation gates.
