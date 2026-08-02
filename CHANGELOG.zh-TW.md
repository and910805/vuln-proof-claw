# Changelog

**繁體中文** | [English](CHANGELOG.md)

重要變更記錄於此。開始版本化 Release 後，格式採用 Keep a Changelog 概念與 Semantic Versioning。

## Unreleased

## [0.1.0] - 2026-08-02

### 新增

- 交付第一條使用者可完成的流程：啟動本機 Compose、輸入一個已授權的公開 URL、執行有界評估、查看 Finding 明細與 Evidence 完整性，並下載 JSON 或 Markdown 報告。
- 新增第一次執行自動建立 Project、瀏覽器記住授權聲明、可見的三階段進度、行內錯誤復原，以及可選的進階 Project 整理。
- 新增以產品結果為中心的 Roadmap；每個里程碑必須先完成一條可用的垂直流程，才擴張 Infrastructure。

### 變更

- 只綁定 loopback 的本機 Compose profile 現在預設啟用有界被動評估；應用程式層級與非本機預設仍停用。
- Dashboard 主要動作改為直接開始評估，不再要求使用者先理解或建立內部 Project 與 Engagement record。
- 進階 Scope、持久化、DNS pinning、限制與 Evidence chain 控制仍在簡化介面背後強制執行。
- Python 與 Web package 版本前進至 `0.1.0`，專案狀態由 pre-alpha 前進至 alpha。

### 安全性

- 簡單流程仍只會針對提交 URL 衍生的確切 hostname、scheme、port 與 path，執行一次無憑證 GET。
- DNS candidate、private-address policy、proxy、redirect、response size、timeout、report metadata 與 Evidence chain 完整性仍各自獨立強制執行。
- 共用或 production deployment 仍須明確啟用並設定 authentication；crawler、form、login、active payload、exploit 與任意工具仍不可用。

## [0.0.21] - 2026-08-02

### 新增

- 新增窄範圍 Worker executor，透過既有 DNS-pinned HTTP transport，執行受 Scope 約束、無憑證的 `public_page_read` L0 GET／HEAD request。
- 新增受保護的 HTTP Action request 契約，在網路 I/O 前驗證 capability、parameter digest、timeout、header、method 與解碼後 response 大小。
- 新增明確授權 loopback 的真實 transport 測試，以及從 Worker capture 到 Evidence、Action 完成與 hash-chain 驗證的端對端整合測試。

### 變更

- 專案與 Web package 版本前進至 `0.0.21`，並新增英文與繁體中文的 executor 邊界文件。
- 不支援的 Worker Action 現在會回傳穩定的 `worker_action_not_supported` policy 結果，不再使用先前的未實作 placeholder。

### 安全性

- Executor 不使用 proxy、驗證所有 DNS 解析位址、拒絕混合公開／私有位址、固定已驗證 IP 並保留 TLS hostname 驗證、拒絕 redirect，且限制 timeout 與 response bytes。
- Authorization、Cookie、request body、POST、登入 session、JavaScript、crawler、browser automation 與任意工具仍不在契約內；未知 transport 細節不會反射。
- 官方 Docker Worker network 仍為 internal，公開 egress 仍停用，需等待另行審查的受控 egress 設計與啟動整合。

## [0.0.20] - 2026-08-02

### Added

- 新增嚴格的 inline `http-v1` Worker capture 契約，支援一筆 GET／HEAD response，並限制 canonical target、allowlist request header、header/body 大小、body digest、capture time 與 duration。
- 新增可信控制面 capture ingestion：重建既有 HTTP evidence 契約、重驗 Action parameter 與 Engagement scope、配置 Evidence ID，並將 canonical content 寫入 transactional hash chain。
- 新增針對協定、Worker manager、lifecycle、持久化、parameter drift、過期 scope、target binding、duration、base64、digest、redirect、HEAD body 與解碼大小的測試。

### Changed

- 成功的 Worker response 可包含已持久化 Evidence ID 或一筆 inline HTTP capture，但不可混用；接受的 inline content 會在 lifecycle response 回傳前換成控制面產生的 Evidence ID。
- 專案與 Web package 版號升至 `0.0.20`，並新增雙語 Worker capture-ingestion 文件。

### Security

- Worker 無法選擇 Evidence ID，也不能直接寫入 Evidence storage。Inline body 不會出現在 representation 或 audit payload。
- 控制面會在持久化前獨立檢查 target／duration binding、受保護 parameter digest、具時間性的持久化 scope、redirect rejection、HEAD 語意、解碼後大小與 body SHA-256。
- 被拒絕的 capture 會以穩定安全錯誤關閉 Action，且不寫入 Evidence；內建 Worker 仍停用網路，因此本邊界不宣稱已完成目標執行。

## [0.0.19] - 2026-08-02

### Added

- 新增有大小上限的 Worker stdin 入口，嚴格驗證一筆真實 v1 request，並在不連線目標、不捏造證據的前提下輸出綁定原請求的終止回應。
- 在既有 SBOM 旁新增綁定原始碼的 container image 身分紀錄，包含 commit、image ID、平台、Dockerfile hash 與可用的 repository digest。
- 新增須明確啟用的 Linux／Docker 端對端測試，以 digest-pinned image 驗證正式 Engine adapter 與完整 hardened Worker lifecycle。

### Changed

- 專案與 Web package 版號升至 `0.0.19`，並記錄協定驗證、本機 image identity、registry publication 與 target-facing execution 的差異。

### Security

- 無效、畸形、空白與超限 Worker 輸入只會產生一筆固定且不反射輸入的錯誤；有效輸入會產生綁定原 request、engagement、action 與 exit code 的嚴格 `policy_denied` 回應。
- Worker 協定驗證不會對目標發出網路請求，也不回傳 evidence 或 artifact ID，避免把基礎設施里程碑誤認為評估成功。
- CI image 帶有必須與身分紀錄一致的 OCI source-revision label；本機 image ID 與 registry publication digest 明確分開處理。

## [0.0.18] - 2026-08-02

### 新增

- 新增必須明確啟用、只透過一個 configured local Unix socket 使用 Docker Engine API v1.44 的 backend，而且只注入獨立 Engine process。
- 新增獨立 policy，只允許一個 digest-pinned Worker image 與一個 dedicated internal network，並檢查 Linux、API version、seccomp、image 與 network readiness。
- 新增固定欄位 create、stdin-only request attachment、start、有界 wait/log decoding、stop、ownership-filtered inventory 與 idempotent forced removal。
- 新增 mocked Engine 聚焦測試，涵蓋完整 lifecycle、精確 Docker request hardening、ownership enforcement、attach cleanup、response bound、raw-stream framing、安全 status mapping、readiness failure、process injection 與設定 gate。

### 變更

- Engine application lifespan 現在會關閉 backend transport resource，process entry point 只在獨立 policy 完整時注入 Docker adapter。
- 專案與 Web package 版號升至 `0.0.18`，並新增雙語 Docker backend 文件與 runtime 狀態更新。

### 安全性

- Docker create request 不含 caller-controlled command、entrypoint、environment、bind mount、device、published port、namespace、privilege、added capability、daemon URL 或 proxy 欄位。
- 每個 post-create operation 都會重新 inspect immutable owner label，以及 hardened image、network、root filesystem、capability、privilege 與 security-option 狀態後才操作 container。
- Docker JSON、declared／streamed bytes、attach header、multiplexed log framing 與 Worker output 都受限；daemon message、socket path、payload 與 opaque ID 不會進入公開 failure。
- Stdin attachment 失敗會強制移除剛建立的 container 與 anonymous volume；create conflict 只對完全相同的 owned request 維持 idempotent。

## [0.0.17] - 2026-08-02

### 新增

- 新增必須明確啟用、獨立啟動的 FastAPI Engine gateway server，實作既有 readiness、create、start、wait、stop、強制移除與 ownership inventory 契約。
- 新增窄版可注入 privileged-backend protocol、安全 backend error 分類，以及在 reviewed Engine adapter 完成前保持 readiness fail-closed 的 disabled backend。
- 新增 loopback binding、Bearer secret、request size、併發操作與有界 queue admission 設定。
- 新增 server 聚焦測試，以及真實的記憶體內 `HttpDockerEngineGateway` client-to-server 完整 lifecycle 測試。

### 變更

- 新增 `vuln-proof-claw-engine` process entry point，並以英文與繁體中文記錄獨立信任邊界及環境設定。
- 專案與 Web package 版號升至 `0.0.17`，並更新 runtime 狀態文件，區分已完成的 gateway service 邊界與待完成的 privileged Engine adapter。

### 安全性

- Authentication 會在 body parsing 與 privileged admission 前執行；宣告與實際串流 request size 都會在 strict schema validation 前受到限制。
- Privileged operation 受到 semaphore 併發限制與短 queue timeout，Worker output 也會在 server 邊界再次檢查。
- Backend error 會縮減為穩定公開 code；未預期 exception 訊息、Engine 細節、不透明 reference、payload 與 secret 都不會透過 response 或 representation 外洩。

## [0.0.16] - 2026-08-02

### 新增

- 新增 authenticated bounded HTTP `RestrictedDockerEngine` client，涵蓋 readiness、create、start、wait、stop、強制 remove 與依 ownership 過濾的 inventory。
- 新增嚴格 gateway wire model，會獨立重新驗證 Worker protocol payload、digest-pinned image、Worker／name／request label、非 root user、硬資源上限、不可變 privilege flag 與必要 tmpfs storage。
- 新增 fail-closed Engine gateway 設定，包含 HTTPS 或明確 loopback IP origin、獨立 32–4096 字元 Bearer secret、可選 private CA bundle、timeout 與 response ceiling。
- 新增 24 項 gateway 測試，涵蓋 authentication、lifecycle 整合、HTTPS 與 loopback policy、有界 streaming／decoding、status 分類、異常 response、直接 schema bypass 與不洩漏 secret 的 failure。

### 變更

- Engine reference 現在只會以不透明 JSON value 傳遞，不會進入 URL path；redirect 與環境 proxy discovery 已停用，而且不會盲目 retry mutating operation。
- 專案與 Web package 版號升至 `0.0.16`，並更新雙語 runtime roadmap 與安全文件。

### 安全性

- 在嚴格 JSON parsing 前，同時限制宣告的 `Content-Length` 與實際串流 response byte；解碼後 Worker output 還會比對獨立上限。
- Gateway response body 與 HTTP detail 不會進入安全 exception。Authentication、conflict、rejection、invalid response、limit 與 availability failure 使用穩定 code。
- 任何環境啟用 runtime 都要求完整 gateway credential；production 還要求 API authentication readiness，而且 Engine token 不得與 API role token 相同。

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
