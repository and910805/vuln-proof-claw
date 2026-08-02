# Worker HTTP Executor

[繁體中文](WORKER_HTTP_EXECUTOR.zh-TW.md) | **English**

Version 0.0.21 adds one deliberately narrow target-facing capability to the
disposable Worker: a scope-bound, credential-free HTTP GET or HEAD request for
the `public_page_read` L0 action. It is an evidence-collection primitive, not an
automatic penetration-testing engine.

## Request contract

The control plane sends a `WorkerHttpAction` containing the method, a canonical
target, allowlisted request headers, and a decoded-response limit. The Worker
accepts only:

- `GET` or `HEAD` with no request body;
- the existing safe request-header allowlist, with no authorization, cookies,
  proxy credentials, or other ambient secrets;
- a timeout of at most 60 seconds; and
- a decoded response body limit from 1 byte through 512 KiB.

The request must carry the `http_client` capability and a parameter digest
recomputed from the method, canonical target, and headers. Any missing,
unsupported, or drifted field fails closed before network I/O.

## Network and response defenses

The executor reuses the DNS-pinned transport. It disables proxy use, resolves
all candidate addresses, and rejects the request unless every candidate is
globally routable or explicitly covered by the engagement's allowed CIDRs.
Mixed public/private DNS answers are therefore rejected. A connection is made
to one validated pinned address while HTTPS certificate validation still uses
the original hostname. Redirects are not followed.

Declared and streamed response sizes are bounded independently. HEAD responses
must not contain a body, and the measured request duration must remain within
the approved timeout. Expected failures are reduced to stable error codes;
unknown transport or exception details are not reflected to the caller.

## Evidence pipeline

On success, the Worker returns one inline `http-v1` capture and no Evidence ID.
The trusted control plane then revalidates the Action digest, target, duration,
persisted time-aware scope, response semantics, decoded size, and body SHA-256.
Only the control plane allocates the Evidence ID and appends canonical content
to the engagement hash chain. The lifecycle response exposes the Evidence ID,
not the inline body.

An integration test exercises this complete path with an explicitly scoped
loopback server: Worker request, DNS-pinned capture, trusted ingestion, Evidence
ID allocation, Action completion, and hash-chain verification.

## Runtime boundary and remaining work

The official Docker Worker network remains `internal: true`. This preserves the
reviewed fail-closed runtime and means the bundled container cannot yet reach a
public target. Controlled container egress, production startup wiring, and a
registry-published image digest remain required before this capability can be
enabled in the official deployment path.

POST requests, credentials, login sessions, JavaScript execution, crawling,
browser automation, exploit payloads, and arbitrary tools are outside this
version's contract.
