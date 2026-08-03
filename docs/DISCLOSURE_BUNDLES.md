# Verifiable Disclosure Bundles

[繁體中文](DISCLOSURE_BUNDLES.zh-TW.md) | **English**

Version 0.6.0 packages an engagement's JSON, Markdown, escaped HTML, and SARIF reports
into one metadata-only ZIP that can be verified without a server or network connection.

## Download and verify

Use **Download verifiable bundle** in the assessment result or history view, or request:

```text
GET /api/v1/engagements/{engagement_id}/report.bundle.zip
```

Verify the downloaded archive locally:

```bash
vuln-proof-claw verify-bundle engagement-disclosure.zip
vuln-proof-claw verify-bundle engagement-disclosure.zip --json
```

The verifier returns non-zero when the ZIP structure, manifest schema, declared file
sizes, SHA-256 digests, safe member paths, or Evidence-chain links are invalid.

## Contents and boundary

- `manifest.json`: generator, engagement, Evidence integrity, file hashes, and the
  metadata-only Evidence-chain index.
- `report.json`, `report.md`, `report.html`, and `report.sarif`: equivalent report views.
- `README.txt`: offline verification instructions and disclosure boundary.

The archive excludes raw HTTP bodies, cookies, browser storage, login credentials,
provider secrets, and environment configuration. The manifest states
`raw_evidence_included: false`, and the verifier rejects a bundle that changes this policy.

The verifier does not extract the archive. It rejects absolute and parent-relative paths,
backslashes, directories, duplicate names, encrypted entries, excessive member counts,
oversized data, suspicious compression ratios, and files not declared by the manifest.

SHA-256 integrity proves that files still match the manifest; it does not identify who
created the archive. Cryptographic signing remains a separate future feature.
