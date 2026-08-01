# Runtime resource janitor

[繁體中文](RUNTIME_JANITOR.zh-TW.md) | **English**

Version 0.0.14 defines and tests the cleanup contract used by a future restricted
runtime adapter. It prevents disposable resources from surviving a control-plane
restart indefinitely. It does not enable target-facing execution by itself.

## Runtime inventory contract

Each application-owned resource must expose immutable, non-secret metadata:

- the control-plane Worker ID;
- the protocol request ID;
- a timezone-aware creation timestamp; and
- an opaque runtime reference used only inside the privileged adapter.

The runtime identity must identify an immutable implementation or image. Inventory
must return only resources owned by this application. Resource creation binds the
Worker ID before the runtime resource exists, and `destroy` must be idempotent.
Opaque references are excluded from result representations, durable records, and
audit payloads.

## Restart order

The startup adapter calls `recover_runtime_after_restart` in one ordered operation:

1. Mark durable `starting` and `running` executions as `lost` and their Actions as
   `worker_lost`.
2. Inventory resources owned by the configured runtime.
3. Preserve resources still bound to a non-terminal registry row.
4. Destroy terminal, stale, mismatched, or unregistered resources.
5. Persist successful cleanup and append a safe audit event.

Unregistered or mismatched resources observe a five-minute grace period by default,
which protects the narrow interval between runtime creation and registry insertion.
Terminal rows do not need that grace period. One sweep is serialized and duplicate
runtime references are destroyed at most once.

## Safe outcomes

Sweep results contain only Worker ID, request ID, status, and a stable reason code.
Runtime exceptions are reduced to `worker_runtime_inventory_failed` or
`cleanup_failed`. If the resource is destroyed but the optimistic registry update
loses a race, the outcome is `registry_update_conflict` and a dedicated audit event
flags the durable consistency issue without recreating the removed resource.

Audit event types are:

- `worker.janitor_destroyed`;
- `worker.janitor_cleanup_failed`; and
- `worker.janitor_registry_update_failed`.

## Current boundary

This release provides the inventory, reconciliation, cleanup, audit, and restricted
container-policy adapter. The privileged Engine transport, worker executor, scoped
egress, and startup wiring are still deliberately absent, so `DisabledWorkerManager`
remains the default and arbitrary tools cannot run.
