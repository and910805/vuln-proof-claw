# Disposable Worker lifecycle preview

[繁體中文](WORKER_LIFECYCLE.zh-TW.md) | **English**

Version 0.0.9 provides an internal, runtime-independent lifecycle coordinator. It is
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

At startup, an orchestrator can reconcile abandoned `starting` and `running`
records. Because a new process cannot safely reattach without a concrete runtime
contract, each record becomes `lost` and its queued or running Action becomes
`worker_lost`. The reconciliation is added to the engagement audit trail.

## Current limits

The privileged runtime manager remains process-local and accepts only an injected
runtime implementation. A restricted Docker adapter, orphan-runtime janitor, DNS
pinning, scoped egress, streaming output limits, and isolated end-to-end target
tests remain required before target-facing execution can be enabled. The default
`DisabledWorkerManager` still fails closed.
