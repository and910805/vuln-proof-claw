# Changelog

**繁體中文** | [English](CHANGELOG.md)

重要變更記錄於此。開始版本化 Release 後，格式採用 Keep a Changelog 概念與 Semantic Versioning。

## Unreleased

## [0.0.15] - 2026-08-16

### 新增

- 新增 `WorkerCaptureCoordinator`：授權已排入佇列的 Action、執行拋棄式 worker，並在轉換 Action 狀態前，將擷取到的回應落地成不可竄改的證據。
- 新增共用的 `CaptureEnvelope` worker 對控制平面的傳輸格式，攜帶完整且有界的回應。
- 讓 worker 在輸出終端回應的同時，也輸出 `CaptureEnvelope`（狀態、標頭與 base64 內容）。
- 新增 Docker-gated 整合測試，涵蓋 worker capture runner 對本地靶機的實際擷取。

### 安全性

- worker 完全不碰資料庫；控制平面握有所有權限並負責證據持久化。
- 落地的證據會進入各 engagement 的雜湊鏈並端到端驗證；實際執行已確認還原的內容與靶機相符、且鏈驗證通過。
- worker 執行失敗、擷取失敗、以及未知或未授權的 Action，一律 fail closed 成 FAILED 狀態並附上穩定的 error code。

## [0.0.14] - 2026-08-16

### 新增

- 將佔位版的 worker entry point 換成真正的拋棄式 worker：執行一次有界的 HTTP capture 並輸出終端 `WorkerResponse`。
- 在沙箱內、送出任何請求前，先重新評估目標的 engagement scope。
- 讓 `DockerWorkerRuntime.wait` 容許診斷輸出：以最後一行可解析的 response 為準。
- 新增 Docker 整合測試：對本地靶機執行真正的 worker，並確認連不到網際網路。

### 安全性

- worker 只做一次不跟隨 redirect 的 `GET`、不送任何憑證，並限制回應內容大小。
- 對超出範圍的目標、redirect 或目標變更、逾時、過大內容與傳輸失敗，一律對應到穩定、不含細節的 error code。
- 實際端到端執行已確認：worker 能擷取範圍內的本地靶機，但在隔離網路上無法連到網際網路主機。

## [0.0.13] - 2026-08-16

### 新增

- 新增具體的 Docker Worker runtime，以強化的拋棄式容器填補 `WorkerRuntime` 介面。
- 新增 fail-closed 的 manager 工廠：未明確啟用 runtime 時一律回傳停用的 worker manager。
- 新增可注入的 Docker CLI 執行器，讓 runtime 可做單元測試；並加入需選擇性開啟的真實 Docker 整合測試。
- 新增帶所有權標籤的容器與 `list_owned` 能力，供 orphan-runtime janitor 回收。

### 安全性

- 每個 Worker 啟動時都 drop 所有 Linux capability、rootfs 唯讀、no-new-privileges，並套用 process／記憶體／CPU 上限。
- Worker 只接上隔離的 worker 網路，因此無法連到公開網際網路。
- 當 `docker.runtime_enabled` 為 false 時拒絕建構或執行，讓 target-facing 執行維持預設停用。
- 對 create、start、wait、cancel、remove、list 的失敗一律回傳穩定、不含細節的 error code。

## [0.0.12] - 2026-08-16

### 新增

- 新增綁定 Engagement 的擷取式瀏覽器認證工作階段登錄表，以及 Alembic revision `0006_authentication_sessions`。
- 新增工作階段服務，以交易方式擷取、撤銷並釋出認證素材，並記錄稽核事件。
- 新增認證工作階段的樂觀版本撤銷，以及以時間與狀態為界的可用性判斷。

### 安全性

- 擷取的素材不會進入 domain model、log 或稽核 payload；僅保留 digest、位元組大小與去識別化的 key 名稱。
- 素材僅透過可用的工作階段釋出給所屬 Engagement，並在釋出前重新計算大小與 SHA-256。
- 對已撤銷、已過期、跨 Engagement、過大或遭竄改的工作階段一律 fail closed。

## [0.0.11] - 2026-08-16

### 新增

- 新增 orphan-runtime janitor，回收沒有存活的行程內擁有者的拋棄式 Worker runtime 資源。
- 新增可回收（reapable）runtime 能力，可列舉並具冪等性地銷毀平台擁有的 Worker。
- 新增系統層級稽核輔助函式，用於不綁定單一 Engagement 的控制平面事件。
- 對外提供 manager 仍擁有的存活 runtime reference，讓並行的清掃永遠不會銷毀仍被追蹤的 Worker。

### 安全性

- 重啟後將所有列舉到的 runtime reference 一律視為孤兒，補上 runtime reference 不持久化所留下的缺口。
- 絕不銷毀受存活 manager 保護的 reference，且列舉失敗時清掃會 fail closed。
- 稽核軌跡僅記錄不含 reference 的回收計數，且對無動作的清掃略過稽核寫入。

## [0.0.10] - 2026-08-01

### 新增

- 新增獨立設定的 `evidence_reader` Bearer role，專門控管敏感內容存取。
- 新增具稽核紀錄、綁定 Engagement，且會驗證完整 Evidence chain 的 raw evidence 下載。
- 新增具 idempotency 的不可變 JSON／Markdown 報告匯出，以及 Alembic revision `0005_report_exports`。
- 新增報告匯出清單與下載前完整性驗證 API。

### 安全性

- Operator 與 approver 無法取得 raw evidence 或報告快照內容。
- 未設定 reader 憑證或 Evidence chain 無效時，raw evidence 存取會 fail closed。
- 報告下載前會重新驗證內容大小與 SHA-256。
- 敏感內容讀取成功時會記錄綁定 actor 的 audit event，不會把 payload 寫入稽核紀錄。

## [0.0.9] - 2026-08-01

### 新增

- 加入持久化 Worker execution registry，並強制一對一 Action 與 request 綁定。
- 加入 Alembic revision `0004_worker_executions` 與 optimistic lifecycle 更新。
- 加入 abandoned `starting`、`running` Worker 紀錄的重啟 reconciliation。

### 安全性

- 資料庫只保存安全的 lifecycle metadata；privileged runtime reference 不會寫入資料庫。
- 無法復原的 in-flight Worker 與 Action 會明確轉為 `lost`／`worker_lost` 終止狀態。
- startup reconciliation 會寫入不可變的 Engagement 稽核軌跡。
- 預設仍停用具體 runtime attachment 與面向目標的執行。

## [0.0.8] - 2026-08-01

### 新增

- 加入可注入 runtime 的拋棄式 Worker manager，涵蓋建立、啟動、收集、逾時、取消與必要清理狀態。
- 加入持久化 Action-to-Worker 協調與生命週期稽核事件。
- 加入 process 內安全的 request replay 檢查與並行 collect／cancel 處理。

### 安全性

- Worker 啟動前重新檢查持久化 Action、Scope、policy 與 Approval 狀態。
- 只在 Action 轉為 `running` 時消耗綁定的 Approval。
- 拒絕不相符的 Worker 回應，以及沒有同一 Action 持久化 Evidence 的成功結果。
- 預設仍停用具體 runtime 與所有面向目標的執行。

## [0.0.7] - 2026-08-01

### 新增

- 新增可選的 API-wide Bearer authentication，以及分離的 operator／approver role。
- 新增具 authentication 的單一 Action 批准／拒絕 decision 與期限限制。
- 新增 operator cancellation，以及包含 actor 的批准、拒絕、取消 audit event。
- 新增 Approval 查詢與執行時單次消耗。

### 安全性

- Authentication readiness 為 false 時，approval mutation 維持停用。
- Approval identity 由部署設定推導，不接受 client 輸入。
- 過期、遺失、遭修改、已耗盡或不符的 Approval 會在 transport 前 fail closed。
- Health probe 維持公開；authenticated mode 會保護其餘所有 v1 API route。

## [0.0.6] - 2026-08-01

### 新增

- 新增具分頁能力的 Flow、Task、Action 與 Engagement audit-event API contract。
- 新增 transactional HTTP Action 提案，以及確定性的風險與 scope policy 結果。
- 新增 Flow、Task、Action 提案與 policy decision 的不可變 audit event。
- 新增 Engagement 範圍的 idempotency replay 與受保護參數衝突偵測。

### 安全性

- 允許的 Action 只會進入 queued，不開放面向目標的實際執行。
- 在 Action 持久化前拒絕不安全 HTTP method 與帶有 credential 的 header。
- Risk 與 policy 結果一律由 server 依持久化的 Engagement scope 推導。

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
