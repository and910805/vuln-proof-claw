# Worker Capture Ingestion

[繁體中文](WORKER_CAPTURE_INGESTION.zh-TW.md) | **English**

Version 0.0.20 adds the trusted ingestion boundary between an untrusted
disposable Worker response and the control-plane evidence chain. It does not
enable Worker network execution.

## Inline contract

A successful Worker may return exactly one `http-v1` capture instead of an
Evidence ID. The capture is limited to GET or HEAD, canonical request and final
targets, allowlisted request headers, bounded response headers, one 512 KiB
decoded body, a body SHA-256 digest, an aware capture timestamp, and a bounded
duration. Redirects, a HEAD body, invalid base64, digest mismatch, mixed inline
captures and Evidence IDs, and captures outside the Worker response window are
rejected by the protocol.

The raw capture is hidden from object representations. Docker, Engine gateway,
and Worker output ceilings remain independent outer bounds.

## Trusted revalidation and persistence

The control plane does not trust a Worker-supplied target, timestamp, method,
headers, duration, or digest. Before persistence it:

1. binds the capture target and duration to the original Worker request;
2. reconstructs the protected `HttpCaptureRequest` and verifies the Action
   parameter digest;
3. evaluates the canonical target against the persisted Engagement scope at
   the capture timestamp;
4. reconstructs the existing `HttpCaptureResponse`, including redirect and
   HEAD-body rules;
5. generates the Evidence ID in the control plane and appends the canonical
   raw capture to the transactional per-Engagement hash chain; and
6. returns a normalized terminal response containing only the new Evidence ID.

Any binding or scope failure closes the Action as failed with a stable safe
error and persists no evidence. The audit event contains Evidence IDs, status,
and safe error codes, never the inline body.

## Remaining gate

The bundled Worker still returns `worker_execution_not_implemented` and makes
no target request. Scoped egress and a narrowly reviewed HTTP executor must be
implemented before this ingestion path can receive live Worker captures.
