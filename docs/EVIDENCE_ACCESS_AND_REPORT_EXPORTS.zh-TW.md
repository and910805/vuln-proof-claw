# Evidence 存取與報告匯出

**繁體中文** | [English](EVIDENCE_ACCESS_AND_REPORT_EXPORTS.md)

0.0.10 版完成一條受控的持久化 Evidence 與 Engagement 報告審閱流程。這項能力
不會執行掃描器，也不會連線到評估目標。

## Role 與就緒條件

先依照[驗證與單一 Action 批准](AUTH_AND_APPROVALS.zh-TW.md)設定 API authentication，
再加入第三組 secret：

```text
VULN_PROOF_CLAW_API__EVIDENCE_READER_IDENTITY=evidence-reader@example.test
VULN_PROOF_CLAW_API__EVIDENCE_READER_TOKEN=<第三組至少 32 字元的隨機 secret>
```

所有已設定的 token 都必須不同。既有 authenticated deployment 可以暫不設定
evidence-reader token，但敏感下載 endpoint 會回覆
`503 evidence_access_not_ready`。Role 邊界如下：

- operator 建立報告快照；
- evidence reader 下載報告內容與 raw evidence；
- approver 不能執行上述兩種操作；
- 敏感內容讀取成功時，audit trail 會記錄設定的 reader identity。

## 不可變報告流程

使用 operator token 與必要的 idempotency key 建立快照：

```http
POST /api/v1/engagements/{engagement_id}/report-exports
Authorization: Bearer <operator token>
Idempotency-Key: final-report-2026-08-01
Content-Type: application/json

{"format":"json"}
```

v0.4.0 另外接受 `sarif`，可建立 SARIF 2.1.0 不可變報告快照。

`format` 接受 `json`、`markdown` 或 `sarif`。以相同 key 與 format 重送時會回傳原始快照；
同一 key 改用另一種 format 則回覆 `409 idempotency_key_conflict`。可由
`GET .../report-exports` 列出 metadata，該 response 不包含內容。

使用 evidence-reader token 呼叫
`GET .../report-exports/{export_id}/download` 下載內容。API 會先重新計算儲存大小與
SHA-256 digest；不一致時回覆 `409 report_export_integrity_failed`。成功 response
包含 `ETag`、`X-Content-SHA256`、`Content-Disposition` 與
`Cache-Control: no-store` header。

## Raw evidence 流程

使用 metadata-only Engagement 報告提供的 Evidence ID：

```http
GET /api/v1/engagements/{engagement_id}/evidence/{evidence_id}/raw
Authorization: Bearer <evidence-reader token>
```

API 會在釋出內容前驗證完整的 Engagement Evidence chain，並確認 Evidence 屬於
路徑指定的 Engagement。無效 chain 回覆 `409 evidence_integrity_failed`；跨
Engagement 與未知 ID 都維持 `404 evidence_not_found` 邊界。Response 的
`X-Content-SHA256` 是 raw content digest，`X-Evidence-Digest` 則是 canonical
Evidence chain digest。

## 目前限制

報告快照與 Evidence payload 目前儲存在控制平面資料庫。外部加密 object storage、
retention policy、reader token rotation、per-project RBAC、browser session 與
Evidence viewer 仍需要後續設計。
