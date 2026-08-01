# Changelog

**繁體中文** | [English](CHANGELOG.md)

重要變更記錄於此。開始版本化 Release 後，格式採用 Keep a Changelog 概念與 Semantic Versioning。

## Unreleased

## [0.0.15] - 2026-08-02

### 新增

- 新增建立於窄化 privileged Engine 介面上的完整受限 `DockerWorkerRuntime` lifecycle，包含 create、start、有界 wait、stop、冪等 remove 與具 label inventory。
- 新增由不可變 policy 產生的 runtime identity、digest-pinned image 驗證、專用 network 驗證、capability allowlist，以及可設定的 CPU、記憶體、PID、timeout、request、output、tmpfs 與 stop 上限。
- 新增 32 項 runtime 測試，涵蓋 hardened container spec、lifecycle 整合、protocol 與 exit-code 驗證、inventory ownership、不安全設定、metadata injection、過大 I/O 與安全 Engine failure。
- 新增雙語受限 runtime 邊界文件及明確的 fail-closed 環境設定。

### 變更

- Worker request 現在只透過有界的嚴格 protocol stdin 進入 container；Engine request 不提供任意 command、entrypoint、environment、host mount、device、privileged、host network 或新增 capability 欄位。
- Runtime inventory label 現在會綁定 owner、Worker ID、request ID、建立時間與完全相符的 policy identity。
- 專案與 Web package 版號升至 `0.0.15`。

### 安全性

- 每個 container spec 都要求非 root、唯讀 root filesystem、`cap_drop=ALL`、`no-new-privileges`、init，以及 `noexec,nosuid,nodev` tmpfs storage。
- Runtime 必須明確啟用、digest-pinned policy 建立採 fail closed、production 啟用要求 API authentication readiness，而且 raw Engine detail、output 與 reference 不會出現在安全 exception 或物件表示。

## [0.0.14] - 2026-08-02

### 新增

- 新增與 runtime 無關的 inventory 契約，使用不可變 Worker／request ownership label，並將 privileged reference 保持為不透明值。
- 新增序列化 orphan-resource janitor：保留執行中的工作、對未登記資源套用有界 grace period，並移除終止、過期或綁定不符的資源。
- 新增有順序的重啟 recovery，先將 abandoned Worker execution 與 Action 標為 lost，再清除其 runtime resource。
- 新增 live resource 保護、重啟清理、綁定與 runtime identity 不符、重複 inventory、cleanup retry、安全錯誤及 optimistic update conflict 的測試。

### 變更

- Worker ID 現在會在建立 runtime 前配置並傳入 adapter，避免 ownership label 在事後才附加。
- 專案與 Web package 版號升至 `0.0.14`，並以英文及繁體中文記錄 runtime cleanup 契約。

### 安全性

- Runtime reference 只保留於 process 內，不會出現在持久化資料、稽核 payload、結果表示或安全 exception。
- Inventory 與 cleanup exception 會轉成穩定 error code；janitor 絕不刪除綁定非終止持久化紀錄的資源。

## [0.0.13] - 2026-08-02

### 新增

- 新增由新到舊、支援分頁與專案篩選的被動評估歷史 API，提供正規化目標、完成時間、Evidence／Finding 數量、安全錯誤碼與報告連結。
- Web 評估工作區新增持久化歷史，可依專案篩選、顯示本地化時間、明確狀態、結果數量與錯誤，並可透過 authentication 下載 JSON／Markdown 報告。
- 新增成功、失敗、空白及專案篩選歷史的 API 整合測試，以及前端 URL contract 測試。

### 變更

- 歷史數量改由 correlated database query 與每頁一次的 audit lookup 聚合，避免逐列載入關聯造成 N+1。
- 響應式歷史列在小螢幕會重排為觸控友善卡片，同時保留可見狀態文字與可用鍵盤操作的報告按鈕。

### 安全性

- 查詢評估歷史是唯讀操作，絕不會產生 target traffic；既有 API authentication 仍會保護正規化目標與報告連結。
- 失敗歷史只公開 audit trail 既有的穩定錯誤碼，不會透過此 endpoint 提供 transport exception 或敏感的原始 Evidence。

## [0.0.12] - 2026-08-01

### 新增

- 新增雙語 Web 評估工作區，能從明確授權的 URL 建立範圍縮到最小的 24 小時 L0 Engagement，並啟動被動評估流程。
- 新增供 authentication deployment 使用的分頁範圍 Operator Bearer Token；只保存於 `sessionStorage`，並提供明確清除控制。
- 新增 assessment 結果狀態、Evidence／Finding 數量、具 authentication 的 JSON／Markdown 報告下載，以及穩定的 `#assessments` deep link。
- 新增 URL／Scope 準備、IP literal 拒絕、credential 拒絕、API authentication header、安全錯誤、idempotency key 與 navigation restore 的前端單元測試。

### 變更

- Web CI 現在會先跑前端單元測試，再執行 TypeScript 與正式資產驗證。
- 改善鍵盤導覽、可見 focus、觸控範圍、reduced motion、響應式評估版面，以及授權與 loading feedback。

### 安全性

- UI 會先移除 query string 與 fragment，拒絕 URL 內嵌 credential、不支援的 scheme 與 IP literal，並要求明確勾選授權確認。Private 與 IP-literal target 必須使用經人工審查的 API Scope。
- UI 顯示狀態不是授權邊界；Server 仍會強制檢查 authentication、role、scope、policy、DNS、transport 與 response limit。

## [0.0.11] - 2026-08-01

### 新增

- 新增 opt-in passive URL assessment API，會建立經 policy 檢查的 Action、擷取 Evidence、產生 deterministic Finding，並提供報告連結。
- 新增不使用 proxy 的 HTTP(S) transport，具 DNS pinning、TLS hostname 驗證、redirect 拒絕、串流 response 上限與明確 private CIDR opt-in。
- 新增 transport security、browser hardening header、版本洩漏與敏感 Cookie flag 分析。
- 新增 idempotent replay、持久化結果查詢、如實 execution readiness、雙語操作文件與 end-to-end 負面測試。

### 安全性

- Target traffic 預設停用，正式環境啟用前必須先達成 API authentication readiness。
- 混合 public/private DNS、denied network、未預期私網位址、無效 Content-Length、超大 body 與 target 變更全部 fail closed。
- 預覽版只會送出固定 `Accept` 與已設定 `User-Agent` 的 GET request；credential、Cookie、redirect、任意 method 與 exploit payload 仍不可用。

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
