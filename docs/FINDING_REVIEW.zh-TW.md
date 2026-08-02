# Finding 審查

v0.4.0 在自動產生 Candidate 與將 Finding 報告為 verified 之間加入明確的人工審查步驟。
審查 Endpoint 只改變 Control Plane 狀態，不會對目標送出新的請求。

## Endpoint

```http
PATCH /api/v1/engagements/{engagement_id}/findings/{finding_id}
Authorization: Bearer <operator token>
Content-Type: application/json
```

```json
{
  "status": "verified",
  "expected_version": 1,
  "comment": "Evidence reviewed by the operator."
}
```

Response 會包含新的 `version`、綁定 Finding 的 Evidence ID 與審查者身分。Client 必須
送出它讀到的版本；版本過期時會回傳 `409 finding_version_conflict`，避免兩位 Operator
無聲覆蓋彼此的決定。

## 狀態規則

- `pending_verification`：明確排入審查。
- `verified`：Evidence 支持的 Finding，可進入 verified 報告；至少需要一筆 Evidence。
- `rejected`：目前 Evidence 不支持此主張。
- `needs_manual_review`：自動結果需要人工決定或更多情境。

每次成功決定都會建立不可變的 `finding.reviewed` Audit Event。選填的 comment 只存放於
Audit payload，不會寫入 Finding title 或 target data。API 啟用 Authentication 時，Endpoint
需要 Operator role。

## 安全邊界

審查 Finding 不會授權新的目標請求、不會擴大 Scope，也不會改變 Action Policy。verified
狀態是由既有 Evidence chain 支持的報告判定；Active Payload 與狀態改變請求仍保持關閉。
