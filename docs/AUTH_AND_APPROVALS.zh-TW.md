# Authentication 與單一 Action Approval

**繁體中文** | [English](AUTH_AND_APPROVALS.md)

0.0.7 版新增 pre-alpha 控制平面 authentication boundary 與職責分離的 approval
workflow。此設計刻意維持精簡：兩組部署端 credential 分別代表 operator 與
approver，health endpoint 則保持公開，供 orchestration probe 使用。

## 運作模式

Authentication 預設關閉，僅供 loopback 本機開發使用。此模式仍可建立 Project 與
Workflow，但 approval mutation 會回傳 `503 authentication_not_ready`。因此未驗證
身分的 process 無法替 L1-L4 Action 增加執行權限。

設定 `VULN_PROOF_CLAW_API__AUTHENTICATION_READY=true` 後：

- 除 health 外，所有 `/api/v1` route 都需要 Bearer token；
- operator token 可建立 Project、Engagement、Flow、Task、Action，並取消尚未終止的
  Action；
- approver token 可讀取控制平面狀態，並批准或拒絕 `pending_approval` Action；
- 兩組 token 必須不同，且至少 32 個字元；
- audit event 使用設定中的 operator／approver identity，不接受 client 自行填入身分。

必要設定：

```text
VULN_PROOF_CLAW_API__AUTHENTICATION_READY=true
VULN_PROOF_CLAW_API__OPERATOR_IDENTITY=operator@example.test
VULN_PROOF_CLAW_API__APPROVER_IDENTITY=security-lead@example.test
VULN_PROOF_CLAW_API__OPERATOR_TOKEN=<至少 32 字元的隨機 secret>
VULN_PROOF_CLAW_API__APPROVER_TOKEN=<另一組至少 32 字元的隨機 secret>
```

Credential 只能透過 `Authorization: Bearer ...` header 傳送。正式環境還必須使用
可信任 reverse proxy 提供 TLS、由 secret manager 注入、遮蔽 access log 並定期輪替
token。Token 不可放入 URL、提交到設定檔、寫入 evidence 或嵌入 browser source。

內建 Web console 目前尚未實作 credential-entry session。啟用 authentication 後，
請先使用具認證能力的 API client，等待 v0.4 session UI 完成。

0.0.10 版可額外設定第三組且不得重複的 evidence-reader identity 與 token。設定後，
此 token 可進行唯讀 API 存取，且是 raw evidence 與不可變報告內容下載 endpoint
唯一接受的 role。Operator 可以建立報告匯出，但不能下載其內容。詳見
[Evidence 存取與報告匯出](EVIDENCE_ACCESS_AND_REPORT_EXPORTS.zh-TW.md)。

## Approval decision

`POST /api/v1/actions/{action_id}/approval-decision` 接受：

```json
{
  "decision": "approve",
  "reason": "Authorized validation",
  "expires_in_seconds": 900
}
```

只有目前為 `pending_approval` 的 Action 能被決定。Approval 期限限制為 60-3600 秒，
且不得超過 Engagement window。每筆 Approval 只能使用一次，並綁定確切的
Engagement、action type、正規化 target、parameter digest 與 risk level。

批准會將 Action 移至 `queued`，但此時尚不消耗次數。Execution coordinator 會在
呼叫 transport 前重新檢查持久化 Scope 與 Approval，接著以原子方式將 Action 設為
`running` 並消耗唯一一次執行。過期、遭修改、遺失或已使用的 Approval 都會在目標
流量產生前 fail closed。

拒絕會直接將 Action 轉為 `denied`。Operator 可透過
`POST /api/v1/actions/{action_id}/cancel` 取消支援的非終止狀態。批准、拒絕與取消都會
把 actor、reason、identifier 與受保護 metadata 寫入不可變 audit trail。

## 目前邊界

這是務實的 pre-alpha Bearer-token boundary，不是最終 multi-user identity system。
目前不提供密碼登入、token 發行／撤銷、federation、browser session 或 per-project
RBAC；這些功能在正式部署前需要獨立的 schema 與 migration 設計。
