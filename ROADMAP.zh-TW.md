# Roadmap

**繁體中文** | [English](ROADMAP.md)

Roadmap 表達預定方向，不保證 Release 日期。

## 交付原則

每個里程碑都必須完成一條使用者能從頭走到尾的流程，而不只是新增內部模組。安全預設
由控制平面在背景強制執行；一般使用者只看到一個主要動作與可選的進階設定。只有會
直接解除下一條可用流程阻塞的 Infrastructure 工作，才提前實作。

## Phase 0 — 基礎建設

- Python 專案、CLI、API health contract、PostgreSQL、Docker Compose。
- Domain、Policy、Approval 與 Evidence 原語。
- Web 控制台基礎：React／TypeScript 外殼、儀表板摘要、建立專案、分頁範圍 Operator access、授權被動評估精靈、可依專案篩選的持久化歷史、報告下載與雙語 UI。
- 雙語治理、CI、Supply-chain check 與 Worker protocol。

## v0.1 — 可用的被動評估 MVP

0.1.0 是第一個使用者可完成的版本：一個本機 Compose 指令、一個 URL 欄位、只需一次
的授權聲明、自動建立 Project 與 Engagement、有界 DNS-pinned capture、Finding 明細、
Evidence 完整性狀態、持久化歷史，以及 JSON／Markdown 報告。

- 一般流程：輸入已授權的公開 URL、執行、查看、下載。
- 進階流程：選擇 Project，或由 API 定義明確 Scope。
- 背景控制：精確 Target Scope、DNS pinning、不使用 Proxy、有界 byte 與 timeout、
  不跟隨 redirect、保守的 GET-only 分析與 Evidence hash chain。
- 明確限制：尚不支援 crawl、登入、提交 form、active payload、exploit 或自動漏洞確認。

## v0.2 — 實用 Web Discovery

0.2.0 交付第一條有界多頁流程：同源解析、每個 Request 重新進行 Scope 與 DNS Policy、
逐頁 Evidence、聚合 Finding，以及固定 Safe（5）、Fast（15）、Deep（30）頁／Request／
Time Budget。

- 從 HTML Link、Asset、Form、`robots.txt`、Sitemap Location、JavaScript API Path、
  OpenAPI／Swagger、GraphQL 與常見 Security File 進行 Discovery。
- Finding 包含 Severity、Remediation、Confidence 與安全轉義 HTML Preview。
- 後續 Discovery 深度：更完整 Sitemap Index、Content-aware Duplicate Suppression
  與 Crawl Progress Streaming。

## v0.3 — 已授權的 Active Testing

0.3.0 交付第一條受控 Active 垂直流程：OpenAPI 語意 Inventory，以及無必要參數
唯讀 Operation 的自動驗證。Web Console 只提供一個安全自動模式，Control Plane 仍逐
Request 執行 Scope、DNS、Evidence、Request Count 與 Time Budget。

- 已交付：OpenAPI 3.x／Swagger 2.0 Inventory、GET／HEAD-only Safe Probe、宣告驗證
  異常 Candidate、Active Budget 狀態，以及 Report／UI 整合。
- v0.3.x 後續：受控 Container Egress、Registry 發布 Worker Digest、隔離 Browser、
  Authenticated Session、經審查的 Parameter Test 與 Service Discovery。
- 會改變狀態的 Check 必須先具備可重用 Approval Preset，才會對使用者開放。

## v0.4 — Autonomous Core

- 具 budget 與 stopping condition 的 Planner、Operator 與獨立 Verifier。
- 即時進度、互動式 Approval、Evidence viewer、Finding review，以及 HTML、SARIF 與
  bug-bounty workflow export。
- Multi-provider Registry 與 capability detection。
- 依 [AI 驅動架構](docs/AI_DRIVER.zh-TW.md)提供 Codex、Claude Code 與其他 Client 使用的
  本機 ProofClaw MCP Server；受管自動化仍使用 Provider API 或經核准的企業 Access Token。

## v0.5 — 安全自動化與 Agent 介面

v0.5.0 交付第一條有界 Autonomous Core 垂直流程：

- 已完成：一次性 Authenticated Chromium Context、經審查的無害 Query／Header／Path 變異，
  以及 deterministic CORS／Authentication／Authorization／輸入驗證比較。
- 已完成：可重用且綁定 Engagement 的 Approval Preset；套用時仍產生精確、單次 Approval。
- 已完成：可稽核的 Planner／Operator／Verifier 計畫與獨立 Comparison Endpoint。
- 已完成：Codex、Claude Code 與相容 Client 可使用的本機 stdio MCP Server。
- 待完成：將 Browser 與 Comparison Execution 接入持久化 Worker Manager、以專用 Secret Store
  保存多 Principal Session Handle、加入即時進度與 Web 操作介面，並只允許 Evidence-backed
  Verifier Decision 將 Candidate 升級。

## v1.0 — 穩定開源版本

- 穩定 REST 與 Plugin API、Upgrade 文件、Security review、簽章 Image 與 SBOM。

## 後續

內網、Active Directory、雲端、行動裝置、團隊、分散式 Worker 與簽章 Plugin Registry 都必須另外取得設計核准。
