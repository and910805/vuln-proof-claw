# 控制平面工作流程 API

**繁體中文** | [English](WORKFLOW_API.md)

0.0.6 版將持久化的 `Engagement -> Flow -> Task -> Action` 模型接到 v1 REST API。
HTTP 動作提案會在同一筆資料庫交易中完成正規化、風險分類、Engagement scope
政策判斷、狀態轉換與稽核紀錄。

這組 API **不會**對目標送出流量。自動允許的動作只會進入 `queued`。在一次性
Worker 能確實執行 DNS pinning、egress scope、資源限制與證據回傳前，實際執行
仍維持停用。

## 生命週期

1. 在既有且已有 scope 的 Engagement 下建立 Flow。
2. 在 Flow 下建立 Task。
3. 使用 idempotency key 提出受限制的 `GET` 或 `HEAD` HTTP Action。
4. Server 正規化 target 與 action type、計算受保護參數 digest、分類風險並判斷政策。
5. Action 會持久化為 `queued`、`pending_approval` 或 `denied`。
6. `action.proposed` 與 `policy.decision` 稽核事件會保存完整判斷路徑。

提案 endpoint 只接受 capture contract 支援的 `Accept` 與 `User-Agent` request
header。認證資訊、Cookie、redirect、body 與任意 HTTP method 都會在 Action 寫入前
遭到拒絕。

## Endpoints

| Method 與 path | 用途 |
| --- | --- |
| `POST /api/v1/engagements/{id}/flows` | 建立測試目標 |
| `GET /api/v1/engagements/{id}/flows` | 分頁列出 Flow |
| `POST /api/v1/flows/{id}/tasks` | 建立規劃工作單位 |
| `GET /api/v1/flows/{id}/tasks` | 分頁列出 Task |
| `POST /api/v1/tasks/{id}/http-actions` | 提出 HTTP capture 並執行政策判斷 |
| `GET /api/v1/engagements/{id}/actions` | 列出持久化的 Action 狀態 |
| `GET /api/v1/actions/{id}` | 讀取單一 Action |
| `GET /api/v1/engagements/{id}/audit-events` | 檢視不可變稽核事件 |

在相同 Engagement 中，以相同 idempotency key 完全重送同一個提案時，會以 HTTP
200 回傳既有 Action。若沿用該 key 卻改變 Task、target、action type、risk 或受保護
request digest，則回傳 HTTP 409。

## 安全邊界

- Scope 與 Engagement policy 一律由持久層載入；client 不能自行指定 policy 結果或
  risk level。
- 未知 action type 會保守分類為 L2。
- 永久禁止的 action type 與 scope 外 target 會持久化為 denied。
- L2-L4 與預設的 L1 提案會停在 `pending_approval`；經過 authentication 且獨立設定的
  approver 可批准或拒絕確切 Action。
- Audit payload 只包含識別碼、正規化 target、digest 與判斷結果，不包含 request
  header value 或 raw evidence。
- Local mode 會記錄 `api:unauthenticated`。Authentication-ready 部署要求 Bearer
  credential，並記錄設定中的 operator 與 approver identity。

內部執行 contract 請見[受控 HTTP capture](HTTP_CAPTURE.zh-TW.md)，報告完整性行為
請見 [Evidence Core 預覽版](EVIDENCE_CORE.zh-TW.md)。
角色與部署要求請見 [Authentication 與單一 Action Approval](AUTH_AND_APPROVALS.zh-TW.md)。
