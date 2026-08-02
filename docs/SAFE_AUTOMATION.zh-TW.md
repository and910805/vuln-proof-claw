# 安全自動化核心

**繁體中文** | [English](SAFE_AUTOMATION.md)

v0.5.0 提供第一個以 API／MCP 為主的 Planner／Operator／Verifier 工作流。它只建立經審查的
Action 與獨立比較結果；既有 Engagement Scope、風險政策、Approval、Worker 與 Evidence
控制仍是唯一執行依據。

## Browser 與登入隔離

`IsolatedBrowserRunner` 每次執行都建立新的 headless Chromium Process 與 Browser Context。
登入 selector 與 `SecretStr` 憑證只存在記憶體；下載與 Service Worker 會被停用，非明確允許主機的
Request 會被中止，Context 與 Process 一律在 `finally` 清除。結果只包含最終 URL、標題、狀態碼、
Screenshot bytes 與遭阻擋的 Request URL，不包含登入資料或 Storage State。

本機可選執行環境：

```bash
python -m pip install --editable ".[browser]"
python -m playwright install chromium
```

隔離 Worker Image 會安裝 Chromium 與作業系統相依套件。

## 經審查的參數變異

`MutationPlan` 支援 Query、少量經審查 Header allowlist，以及精確 Path value 替換。計畫必須包含
Reviewer 身分與理由、最多八個變異，並產生 canonical SHA-256 digest。內建策略只有空值、整數邊界、
型別錯配與無害 validation marker。Authorization、Cookie、Host、forwarding 等敏感 Header 不可變異。

輸入驗證自動化會拒絕沒有經審查變異的計畫。計畫內容變更就會產生不同 digest，因此不能重用原本的
精確 Approval。

## 安全比較

- CORS：偵測帶 Credentials 的 wildcard origin，以及缺少 `Vary: Origin` 的 credentialed reflection。
- Authentication：比較 anonymous 與 authenticated observation。
- Authorization：比較低權限與高權限 observation。
- 輸入驗證：比較 baseline 與經審查的無害變異，並標記新出現的 Server Error。

結果只有 `pass`、`candidate` 或 `inconclusive`。Candidate 不會自動成為 verified Finding；其 Evidence
與授權假設仍必須經 Verifier 或人工審查。

## Approval Preset

通過驗證的 Approver 可建立 Engagement-scoped Preset，指定 Action type、Target prefix、最高風險與
Approval TTL。Operator 只能將它套用到符合條件的 `pending_approval` Action。每次套用仍建立新的精確
Approval，綁定 Action type、normalized target、parameter digest、risk、期限，且只能執行一次。
Preset 永遠不會擴大 Engagement Scope。

## Planner／Operator／Verifier API

`POST /api/v1/engagements/{id}/automation-plans` 會建立一個 Flow、每個 Check 一個 Task、經 Policy
評估的 Action、適用時的 Mutation digest，以及不可變的 `automation.plan_created` Audit Event。
`POST /api/v1/automation/verify` 執行獨立 deterministic 比較。實際 Target Execution 仍必須通過既有
Action／Approval／Worker 路徑。

本版不提供破壞性 Payload、無限制掃描、任意 Browser Script、跨 Scope Login、自動權限提升，或把
Candidate Finding 自動標示為 verified。
