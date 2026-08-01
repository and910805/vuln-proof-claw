# 受控 HTTP Capture Contract

**繁體中文** | [English](HTTP_CAPTURE.md)

v0.1 Capture Coordinator 是內部 orchestration 邊界，不是公開掃描 endpoint。它只接受既有且狀態為 queued 的 Action，而且受保護參數 digest 必須與實際 request 完全一致。

## 強制條件

- 只接受 `GET` 與 `HEAD`。
- Target 必須已正規化，且符合已保存的 Engagement Scope。
- Request header 僅允許 `Accept` 與 `User-Agent`；credential 與 cookie 一律拒絕。
- 拒絕 redirect 與 final target 變更。
- Timeout 限制為 1–60 秒。
- Response body 上限 10 MiB，預設為 1 MiB。
- `HEAD` response 若包含 body 會被拒絕。
- 成功時會把 canonical request/response envelope 寫入持久化 Evidence chain。
- Transport 失敗時會正常提交狀態為 `failed` 的 Action，並附安全 error code。

## 網路邊界

這個版本沒有啟用具體 network transport。Coordinator 只接收符合內部 contract 的 injected transport。正式 transport 必須執行於一次性 Worker 邊界內、停用 redirect、固定 DNS 解析結果、對每次連線強制執行 CIDR／port／scheme／path Scope，並在串流階段限制 bytes，而不是完整讀入後才檢查。

這項分離是刻意設計：控制平面內的一般 HTTP client 無法自行安全處理 DNS rebinding 與 redirect Scope。
