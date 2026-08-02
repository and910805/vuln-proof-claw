# Worker Protocol Verification

[繁體中文](WORKER_PROTOCOL_VERIFICATION.zh-TW.md) | **English**

Version 0.0.19 makes the restricted Worker image consume one bounded v1
`WorkerRequest` from standard input. A valid request receives a strict,
request-bound `WorkerResponse` with `policy_denied` and
`worker_execution_not_implemented`. The Worker performs no target network
request and creates no evidence or artifact IDs. Invalid and oversized input
receives only a fixed error envelope and is never reflected to output.

This is a protocol and container-lifecycle milestone, not a target executor.
It proves that request attachment, bounded output, exit-code matching, and
control-plane correlation work without presenting mocked evidence as success.

## CI image identity

The container workflow binds each image to the source commit with the OCI
revision label. It uploads a strict JSON identity record alongside each SBOM.
The record includes the local image ID, source revision, platform, Dockerfile
hash, and any repository digest reported by Docker. A local image ID is not a
registry publication digest and must not be used as the runtime allowlist.

## Opt-in live verification

The live test is disabled by default. On a Linux host with an internal Worker
network and a registry digest-pinned image already present, set:

```text
VULN_PROOF_CLAW_RUN_WORKER_INTEGRATION=1
VULN_PROOF_CLAW_TEST_WORKER_IMAGE=registry.example/worker@sha256:<64 hex>
VULN_PROOF_CLAW_TEST_WORKER_NETWORK=vuln-proof-claw-workers
```

Then run `pytest tests/integration/test_live_worker_runtime.py`. The test uses
the production Docker Engine adapter, creates and removes one hardened Worker,
and expects the safe request-bound denial. It never contacts the target URL.
