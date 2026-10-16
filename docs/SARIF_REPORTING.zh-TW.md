# SARIF 報告

v0.4.0 將目前的 Engagement Report 以 SARIF 2.1.0 提供給 Code Scanning 與安全報告流程。
內容只有 Metadata 與 Finding Location，不會嵌入原始 HTTP Body。

## 直接報告

```http
GET /api/v1/engagements/{engagement_id}/report.sarif
```

Response 使用 `application/sarif+json`，只將 `verified` Finding 列為 Result。每個 Result
包含 `proofclaw_*` properties：審查狀態、Confidence、Finding ID、Evidence ID、Remediation
與 Finding record version。Candidate、Pending、Manual-review 及 Rejected Finding 仍會出現在
Engagement 的 JSON、Markdown 與 HTML 報告。Severity 對應 SARIF level：

| ProofClaw Severity | SARIF Level |
| --- | --- |
| critical、high | error |
| medium | warning |
| low、informational | note |

若已驗證 Finding 的連結 Evidence 遺失、屬於另一 Engagement，或完整性檢查失敗，
報告請求會失敗，不會匯出這項主張。

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
Credential。下載或重複使用 Idempotency Key 前，API 會核對 SHA-256 Digest，並重新檢查
匯出內已驗證主張的目前 Finding 狀態與連結 Evidence。若主張後來遭拒或 Evidence 失效，
歷史匯出就不能下載或重放。

SARIF export 是交換／報告功能，不代表授權執行 Scanner。既有 Scope、DNS、Evidence 與
Budget 控制仍是唯一可對目標發送請求的路徑。
