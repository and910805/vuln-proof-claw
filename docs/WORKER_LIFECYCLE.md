# Disposable Worker lifecycle preview

[繁體中文](WORKER_LIFECYCLE.zh-TW.md) | **English**

Version 0.0.15 provides an internal lifecycle coordinator and restricted-container
policy adapter. It is
not a public scanning endpoint and does not enable a Docker or network execution
adapter.

## Enforced sequence

1. Load the queued Action and compare every protected Worker field with durable
   Action and Scope state.
2. Re-run policy and approval checks.
3. Create a stopped disposable Worker.
4. Atomically move the Action to `running` and consume its bound Approval.
5. Start the Worker, collect one terminal response, and always attempt cleanup.
6. Persist `succeeded`, `failed`, `timed_out`, `cancelled`, or `worker_lost` and
   append create/start/collect/cancel/destroy audit events.

A successful response must reference at least one persisted Evidence record, and
every referenced record must belong to the same Action. Missing or cross-Action
Evidence changes the durable Action result to `failed`.

## Durable registry and restart behavior

Lifecycle metadata is stored in `worker_executions` with optimistic versions and
unique Action and request bindings. The registry stores the Worker ID, runtime
identity, state, timestamps, cleanup result, and safe error code. It deliberately
does not store the privileged runtime reference.

At startup, an adapter can run the combined recovery operation. It first reconciles
abandoned `starting` and `running` records to `lost` and their queued or running
Actions to `worker_lost`. It then inventories application-owned runtime resources,
preserves live bindings, and destroys terminal or orphaned resources. Both stages
append safe engagement audit events. See [Runtime resource janitor](RUNTIME_JANITOR.md).

## Current limits

The process-local lifecycle now accepts a complete restricted-container policy
adapter with digest pinning, fixed privilege controls, resource ceilings, bounded
protocol I/O, inventory, and cleanup. A privileged authenticated Engine transport,
scoped egress, worker executor, startup wiring, and isolated end-to-end target tests
remain required before target-facing execution can be enabled. The default
`DisabledWorkerManager` still fails closed.
