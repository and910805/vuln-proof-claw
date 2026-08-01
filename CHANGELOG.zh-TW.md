# Changelog

**繁體中文** | [English](CHANGELOG.md)

重要變更記錄於此。開始版本化 Release 後，格式採用 Keep a Changelog 概念與 Semantic Versioning。

## Unreleased

## [0.0.5] - 2026-08-01

### Added

- 新增與 transport 實作無關的內部 structured `GET`／`HEAD` Capture Coordinator。
- 透過 canonical parameter digest 與持久化 Scope policy，把 request 綁定至 queued Action。
- 新增有大小限制的 canonical HTTP evidence envelope 與明確 transport failure outcome。

### Security

- 拒絕 credential、cookie、redirect、target 變更、過大 body 與不安全 method。
- 在一次性 Worker DNS 與 egress enforcement 完成前，不啟用具體 network transport。

## [0.0.4] - 2026-08-01

### Added

- 新增 transactional raw evidence 持久化、canonical metadata 與每個 Engagement 的 chain index。
- 新增預設 10 MiB payload 限制，以及嚴格的 Action／Engagement 綁定。
- 新增資料庫 evidence chain 重算驗證，並在 Engagement 報告呈現完整性狀態。
- 新增 Alembic revision `0003_evidence_payloads`。

### Security

- 原始證據維持內部使用，不會透過尚未驗證身分的 pre-alpha API 對外提供。
- 資料庫驗證可偵測內容竄改、chain link 中斷、index 缺漏與 payload size 不符。

## [0.0.3] - 2026-08-01

### Added

- 為具備時間範圍的評估任務保存正規化的允許／拒絕 Scope 政策。
- 新增 Engagement 建立、列表、詳細資料與離線 Scope 判斷 API contract。
- 新增僅含 metadata 的 JSON 與 Markdown 評估報告。
- 新增 Alembic revision `0002_engagement_scopes` 與 Evidence Core 預覽文件。

### Security

- Scope 判斷維持離線執行，hostname 結果會標記需要在執行時重新檢查 DNS。
- 報告不包含原始證據，面向目標的執行仍維持 fail-closed。

## [0.0.2] - 2026-08-01

### Added

- 新增根目錄 `VERSION` 版次標記，以及 Python 與 Web 套件版次一致性測試。
- Web 控制台顯示目前執行中的 API 版次。

### Changed

- 本機安裝流程會先安裝仍受安全支援的 `pip`，再執行相依套件稽核。
- 統一產生後 Web 資產的換行格式，避免 Windows 建置產生無意義差異。

## [0.0.1] - 2026-07-30

### Added

- 完全獨立設計的雙語平台規格。
- 雙語 Phase 0 實作計畫。
- Python package 與初始 CLI 骨架。
- 初始雙語開源治理文件。
- 內建雙語 React／TypeScript Web 控制台，提供即時 readiness、儀表板數量與建立專案。
- 版本化 Dashboard 與 Project REST API contract。

### Security

- 文件化尊重 EDR 的開發政策。
- 定義授權用途、Private Reporting、Scope、Approval、Worker isolation 與 Evidence integrity 要求。
- 尚未完成的目標執行功能維持明確鎖定，所有授權判斷仍由 Server 強制執行。
