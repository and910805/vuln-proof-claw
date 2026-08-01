# Roadmap

**繁體中文** | [English](ROADMAP.md)

Roadmap 表達預定方向，不保證 Release 日期。

## Phase 0 — 基礎建設

- Python 專案、CLI、API health contract、PostgreSQL、Docker Compose。
- Domain、Policy、Approval 與 Evidence 原語。
- Web 控制台基礎：React／TypeScript 外殼、儀表板摘要、建立專案與雙語 UI。
- 雙語治理、CI、Supply-chain check 與 Worker protocol。

## v0.1 — Evidence Core

目前預覽進度：已完成持久化且正規化的評估範圍、Flow／Task／Action 提案 API、具 authentication 的單一 Action approval decision、執行時 Approval 消耗、不可變稽核軌跡、transactional raw evidence chain、獨立授權且留有稽核紀錄的 raw evidence 讀取、具完整性狀態的報告、不可變報告匯出、資料庫重驗證、fail-closed HTTP capture contract，以及具持久化 registry 與重啟 reconciliation 的拋棄式 Worker lifecycle。具體受限 runtime、orphan-runtime janitor 與 browser authentication session 仍在進行中。

- Project、Engagement、Scope 與 Action persistence。
- 結構化 HTTP Request/Response capture。
- 拋棄式 Worker lifecycle（持久化 registry 與 fail-closed 重啟 reconciliation 已完成；受限 runtime 待完成）。
- Evidence hash chain 與 Markdown/JSON report。

## v0.2 — Autonomous Core

- Planner、Operator 與獨立 Verifier。
- Multi-provider Registry 與 capability detection。
- Approval workflow、budget、stopping condition 與 audit trail。

## v0.3 — Web/API 能力基準

- Crawl、directory、JavaScript、OpenAPI 與 GraphQL discovery。
- Authentication differential testing、隔離 Browser 與基礎 nmap。
- Restricted shell/Python、精選 Playbook、HTML/SARIF/bug-bounty report。

## v0.4 — Web Experience

- 即時 Flow、互動式批准決策、Evidence viewer、Finding review 與 Report preview。
- Authentication、Session hardening、Accessibility audit 與正式環境 UI 部署控制。

## v1.0 — 穩定開源版本

- 穩定 REST 與 Plugin API、Upgrade 文件、Security review、簽章 Image 與 SBOM。

## 後續

內網、Active Directory、雲端、行動裝置、團隊、分散式 Worker 與簽章 Plugin Registry 都必須另外取得設計核准。
