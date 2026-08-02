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

- 具 page／request／time budget 的同源有界 crawler。
- `robots.txt`、sitemap、JavaScript URL、OpenAPI、GraphQL 與常見 security file discovery。
- Finding 去重，加入 severity、remediation、confidence 與 HTML report preview。
- Safe／Fast／Deep preset；詳細限制維持可選的進階設定。

## v0.3 — 已授權的 Active Testing

- 受控 container egress、registry 發布的 Worker digest 與啟動整合。
- 精選且非破壞性的 active check、隔離 Browser、authenticated session、OpenAPI
  parameter test 與基礎 service discovery。
- 對可能影響目標狀態的 Action 提供可重用 Approval preset。

## v0.4 — Autonomous Core

- 具 budget 與 stopping condition 的 Planner、Operator 與獨立 Verifier。
- 即時進度、互動式 Approval、Evidence viewer、Finding review，以及 HTML、SARIF 與
  bug-bounty workflow export。
- Multi-provider Registry 與 capability detection。

## v1.0 — 穩定開源版本

- 穩定 REST 與 Plugin API、Upgrade 文件、Security review、簽章 Image 與 SBOM。

## 後續

內網、Active Directory、雲端、行動裝置、團隊、分散式 Worker 與簽章 Plugin Registry 都必須另外取得設計核准。
