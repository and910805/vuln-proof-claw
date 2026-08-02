# SARIF 報告

v0.4.0 將目前的 Engagement Report 以 SARIF 2.1.0 提供給 Code Scanning 與安全報告流程。
內容只有 Metadata 與 Finding Location，不會嵌入原始 HTTP Body。

## 直接報告

```http
GET /api/v1/engagements/{engagement_id}/report.sarif
```

Response 使用 `application/sarif+json`，每個 Result 包含 `proofclaw_*` properties：審查
狀態、Confidence、Finding ID、Evidence ID、Remediation 與 Finding record version。Severity
對應 SARIF level：

| ProofClaw Severity | SARIF Level |
| --- | --- |
| critical、high | error |
| medium | warning |
| low、informational | note |

Rejected Finding 仍保留在報告中以維持可稽核性，並附上 `Rejected during review` 的 SARIF
suppression。

## 不可變匯出

Operator 可使用報告匯出 Contract 建立儲存快照：

```http
POST /api/v1/engagements/{engagement_id}/report-exports
Authorization: Bearer <operator token>
Idempotency-Key: sarif-<engagement>-<revision>
Content-Type: application/json

{"format":"sarif"}
```

系統會持久化 Digest、Size 與 Media Type。下載儲存的 Bytes 需要專用 Evidence-reader
Credential，API 回傳前也會驗證 SHA-256 Digest。

SARIF export 是交換／報告功能，不代表授權執行 Scanner。既有 Scope、DNS、Evidence 與
Budget 控制仍是唯一可對目標發送請求的路徑。
