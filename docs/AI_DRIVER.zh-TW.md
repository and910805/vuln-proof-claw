# AI 驅動架構

[English](AI_DRIVER.md) | **繁體中文**

ProofClaw 將 AI coding agent 視為選配的規劃與互動層。Agent 可以把「評估這個網站並解釋
報告」轉成具型別的 ProofClaw 工具呼叫，但不能取代目標 Scope、隔離擷取、Evidence
保存或 deterministic Finding 產生流程。

## 建議產品模式

### 個人本機模式

使用者以自己的訂閱登入 Codex 或 Claude Code，再連接本機 ProofClaw MCP Server。
ProofClaw 只暴露窄而明確的工具，例如：

- `create_assessment(target, preset)`
- `get_assessment(id)`
- `get_report(id, format)`
- `list_findings(project)`

Agent 使用使用者既有的本機 Session，ProofClaw 不接收也不保存模型憑證。所有對目標的
動作仍必須通過 ProofClaw 的授權聲明、Scope Policy、Budget 與 Audit Trail。

### 受管 API 模式

伺服器部署、團隊、排程與無人值守自動化使用 Provider API，或經核准的企業 Access
Token。每個 Tenant 自行提供或負擔模型用量。禁止將個人訂閱 Session 檔案上傳、跨使用者
共用、打包進 Container，或暴露給公開服務。

### 無 AI 模式

每次評估都必須能透過 Web Console 與 REST API 完成，不依賴任何 AI Provider。AI 故障、
額度耗盡或 Provider 無法使用時，不能阻止使用者執行或閱讀 deterministic assessment。

## 信任邊界

```text
使用者對話
    |
Codex / Claude Code / 其他 MCP Client
    |  typed MCP tool call
ProofClaw Control Plane
    |  Scope + Policy + Budget + Audit
隔離 HTTP／Browser Worker
    |  immutable Evidence
Analyzer 與 Report Generator
```

Agent 輸出一律視為不可信輸入。ProofClaw 驗證每個 Tool Argument 並回傳結構化結果。
Agent 不能自行授權、擴大 Scope、停用 Evidence、選擇無上限模式，或執行任意面向目標的
Command。

## 交付順序

1. 先透過 REST 穩定 v0.3 Discovery、安全主動驗證與 Report。
2. 在穩定 Application Contract 上增加本機 stdio MCP Server。
3. 發布 Codex 與 Claude Code 的 Project-scoped 安裝設定。
4. 加入可 Resume 的 Assessment Resource 與進度通知。
5. Provider Adapter 只用於選配 Planner／Verifier；Scanner Core 維持 Provider-neutral。

這個順序讓核心在沒有 AI 時仍能使用，也避免任何單一 Provider 成為安全邊界的一部分。
