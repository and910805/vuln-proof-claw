# Finding 審查

**繁體中文** | [English](FINDING_REVIEW.md)

Review Endpoint 讓 Operator 判斷 Candidate 的既有 Evidence 是否支持 verified 主張。
它只改變 Control Plane 狀態，不會對目標送出請求。部分決定性的直接觀察檢查也會跳過
此 Endpoint，直接建立 `verified` Finding。整體準則請見
[Finding 驗證模型](FINDING_VALIDATION.zh-TW.md)。

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
  "verification_method": "observed",
  "comment": "擷取的回應直接顯示所主張的 Header 缺失。"
}
```

Candidate 可以在此 Request 指明 `verification_method` 為 `observed` 或 `differential`。
差異比較的審查也可以加入由其他已授權 Action 擷取的 `control_evidence_ids`。這些欄位只
描述既有 Evidence，不會執行重測。

Response 會包含新的 `version`、綁定 Finding 的 Evidence ID 與審查者身分。Client 必須
送出它讀到的版本；版本過期時會回傳 `409 finding_version_conflict`，避免兩位 Operator
無聲覆蓋彼此的決定。

## 狀態規則

- `pending_verification`：明確排入審查。
- `verified`：Operator 明確宣稱現有 Evidence 支持具體主張。至少需要一筆測試 Evidence、
  明確的 `observed` 或 `differential` 方法，以及非空白的審查理由；`differential` 主張
  還需要獨立的對照 Evidence。
- `rejected`：目前 Evidence 不支持此主張。
- `needs_manual_review`：自動結果需要人工決定或更多情境。

接受 `verified` 前，API 會驗證整條 Engagement Evidence Chain，並檢查每筆連結的測試或
對照 Evidence 都存在且屬於 Finding 所在的 Engagement。Evidence 遺失、跨 Engagement 或
完整性無效時會阻止升級。審查理由只存於不可變的 `finding.reviewed` Audit Event，
不會寫入 Finding title 或 target data。其他成功的審查決定也會建立該 Event；其 comment
仍可省略。API 啟用 Authentication 時，Endpoint 需要 Operator role。

對 `differential` Finding，若測試與對照擷取的原始位元組完全相同，關卡也會以
`finding_control_not_distinct` 拒絕。位元組不同只是基本合理性檢查，不能證明改變的是
正確變因，也不能證明差異足以支持主張。

報告會分開列出測試與對照的 Evidence ID，讓讀者能區分支持主張的擷取結果與作為比較的紀錄。

此關卡檢查 Evidence 的來源與完整性，不判斷漏洞主張的語意是否成立。目前尚未證明所屬
Action 執行成功、Action 目標與 Finding 目標一致，或回應足以證明所主張的安全影響。
這些檢查需要依 Evidence 建立的型別化 Verifier 及針對目標的重測；Operator 標記 verified
前仍須審查主張與其他合理解釋。

## 安全邊界

審查 Finding 不會授權新的目標請求、不會擴大 Scope，也不會改變 Action Policy。`verified`
是報告判定，不代表可利用性已獲證明。任何重測都需要獨立且通過 Scope／Policy 檢查的
Action，必要時也需要 Approval。
