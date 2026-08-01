# Disposable Worker lifecycle preview

[繁體中文](WORKER_LIFECYCLE.zh-TW.md) | **English**

Version 0.0.14 provides an internal, runtime-independent lifecycle coordinator. It is
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

The privileged runtime manager remains process-local and accepts only an injected
runtime implementation. The runtime-neutral orphan cleanup contract is complete,
but a restricted Docker adapter, DNS pinning, scoped egress, streaming output limits,
startup wiring, and isolated end-to-end target tests remain required before
target-facing execution can be enabled. The default `DisabledWorkerManager` still
fails closed.
