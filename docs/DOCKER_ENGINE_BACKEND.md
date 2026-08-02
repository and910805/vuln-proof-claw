# Restricted Docker Engine backend

[繁體中文](DOCKER_ENGINE_BACKEND.zh-TW.md) | **English**

Version 0.0.18 adds the privileged adapter behind the authenticated Engine gateway.
It uses Docker Engine API v1.44 over a configured local Unix socket. It never invokes
the Docker CLI, reads `DOCKER_HOST`, follows redirects, discovers proxies, or accepts
an arbitrary daemon URL.

## Independent policy gate

The backend remains disabled unless all of these values are explicit:

- an absolute POSIX Unix-socket path;
- one exact registry image reference pinned by `sha256` digest; and
- one dedicated Worker network name.

Readiness requires a compatible Linux Engine, active seccomp support, an available
allowed image, and an existing Docker network marked `Internal=true`. Runtime assets
are checked again before every create operation.

## Fixed create request

The adapter constructs the Docker JSON body itself. The gateway caller cannot add or
override fields. Containers always use the exact allowed image and internal network,
a non-root user, read-only root, `CapDrop=ALL`, no added capabilities, no bind mounts,
no published ports, `no-new-privileges`, PID/CPU/memory ceilings, bounded tmpfs,
disabled auto-remove, and a bounded single-file log configuration.

There are no caller-controlled command, entrypoint, environment, host mount, device,
privileged, namespace, or socket fields. The strict Worker request is sent through
Docker's stdin-only attach channel before start and is never placed in labels,
environment variables, command arguments, or Engine logs.

## Ownership and response handling

Every operation after create accepts only a 64-character lowercase container ID and
re-inspects the container. The immutable owner label, exact image, internal network,
read-only root, dropped capabilities, non-privileged mode, and
`no-new-privileges` setting must still match. Inventory accepts only known ownership
labels and re-inspects every result.

Docker JSON bodies, declared lengths, streamed bytes, attach headers, multiplexed log
frames, and decoded Worker output are bounded before parsing or allocation. Docker
messages and socket paths become stable backend error codes. If stdin attachment
fails, the newly created container is force-removed with anonymous volumes.

Create conflicts are idempotent only when the existing same-name container has the
exact requested labels and still passes ownership inspection. Removal is idempotent
only for an already-absent ID; the adapter never removes a foreign or weakened
container.

## Deployment status

The adapter and its mocked Engine contract are complete. A live Docker integration
test was not run for this release because the local daemon was unavailable. Compose
does not mount the Docker socket and runtime startup remains disabled. Published image
digests, scoped egress enforcement, process isolation, and an isolated live fixture
must be completed before enabling target-facing execution.
