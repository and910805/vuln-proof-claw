# Restricted Docker runtime boundary

[繁體中文](RESTRICTED_RUNTIME.zh-TW.md) | **English**

Version 0.0.15 implements the runtime-neutral security policy and complete
`WorkerRuntime` lifecycle used before any privileged Docker transport is connected.
It remains disabled by default and does not make arbitrary security tools runnable.

## Trust boundary

`DockerWorkerRuntime` does not receive a Docker socket or a general Docker client.
It depends on a narrow `RestrictedDockerEngine` interface that a future authenticated
socket proxy or isolated execution service must implement. The interface accepts a
complete `RestrictedContainerSpec`; there are intentionally no command, entrypoint,
environment, host mount, device, privileged-mode, host-network, or added-capability
escape hatches.

Every emitted spec enforces:

- an image pinned by a lowercase SHA-256 digest;
- a dedicated network that cannot be `host`, `bridge`, `none`, or `control-plane`;
- non-root UID/GID `10002:10002`;
- a read-only root filesystem, `no-new-privileges`, init, and `cap_drop=ALL`;
- bounded CPU, memory, PID, timeout, request, response, and tmpfs sizes;
- `noexec,nosuid,nodev` task and temporary tmpfs mounts;
- a fixed image entrypoint with the strict Worker request delivered through bounded
  stdin; and
- immutable Worker ID, request ID, creation time, owner, and runtime-identity labels.

## Request and response enforcement

The adapter rejects capabilities outside its allowlist and any request limit above
the configured ceiling before contacting the Engine. Worker IDs must be canonical
UUID values, request IDs cannot contain control characters, and serialized requests
must fit the configured byte limit.

The Engine must bound stdout while collecting it. The adapter then validates the
strict `v1` `WorkerResponse`, verifies the reported exit code against the Engine exit
code, and returns only the protocol object. Invalid or oversized output becomes a
stable error code; raw output and privileged references are not included in object
representations or public exceptions.

## Identity and inventory

Runtime identity includes both the digest-pinned image and a SHA-256 digest of every
security-relevant policy field. Changing resource ceilings, network, user, tmpfs, or
capability allowlists therefore creates a different identity. Inventory is filtered
by owner and exact runtime identity, then validates all immutable labels before
returning a janitor resource.

## Configuration gate

`VULN_PROOF_CLAW_DOCKER__RUNTIME_ENABLED` defaults to `false`. Building a policy
requires explicit enablement and a digest-pinned image. Production configuration also
requires API authentication readiness. These checks do not replace authorization,
Scope, Approval, or the worker-local network policy.

## Deliberately pending

This release does not provide a Docker socket mount, Docker CLI subprocess, TCP Docker
API client, or startup wiring. A dedicated authenticated Engine gateway, scoped
egress enforcement, digest publication workflow, worker-side executor, and isolated
end-to-end target tests must be implemented and security-reviewed before the runtime
can be enabled.
