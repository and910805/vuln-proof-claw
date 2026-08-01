# Evidence Core 預覽版

**繁體中文** | [English](EVIDENCE_CORE.md)

v0.1 預覽版把持久化且正規化的評估範圍連接到控制平面 API，但刻意不啟用任何面向目標的執行功能。

## 已提供

- 在既有專案下建立及列出具備時間範圍的評估任務。
- 每個評估任務保存一份正規化的允許／拒絕範圍政策。
- 在不連線目標的前提下，判斷候選 URL 是否符合已保存範圍。
- 產生僅含 metadata 的 JSON 與 Markdown 評估報告。
- 使用 Alembic revision `0002_engagement_scopes` 升級既有資料庫。

## API

- `POST /api/v1/projects/{project_id}/engagements`
- `GET /api/v1/projects/{project_id}/engagements`
- `GET /api/v1/engagements/{engagement_id}`
- `POST /api/v1/engagements/{engagement_id}/scope/evaluate`
- `GET /api/v1/engagements/{engagement_id}/report`
- `GET /api/v1/engagements/{engagement_id}/report.md`

建立範圍時至少需要一個允許的 hostname 或 CIDR。Hostname、network、port、scheme 與 path 都會在保存前正規化。Scope 預設繼承 Engagement 時間範圍，而且不能超出該時窗；拒絕規則優先，未知目標一律採取 fail-closed。

## 安全邊界

範圍判斷是純控制平面決策，不會解析 DNS、傳送 HTTP 請求、跟隨 redirect 或建立 Worker。Hostname 判斷結果會標示 `requires_dns_recheck`；未來的執行 adapter 必須在每次連線與 redirect 時重新解析並強制套用核准的網路邊界。

系統目前可 transactional 保存原始證據與 canonical metadata，並由資料庫內容重新驗證完整性。原始 payload 維持內部使用，報告只呈現完整性狀態與安全 metadata。process-local Worker lifecycle 會驗證成功結果引用的 Evidence；具體面向目標的 runtime、具備身分驗證的證據存取與報告匯出 artifact，仍是 v0.1 後續實作關卡。
