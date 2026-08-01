# 受控 HTTP 擷取契約

**繁體中文** | [English](HTTP_CAPTURE.md)

Capture Coordinator 是內部執行邊界，只接受已存在、狀態為 `queued`，且受保護參數摘要與請求完全一致的 Action。0.0.11 版透過預設關閉的被動評估 API 使用這個邊界。

## 強制不變條件

- Coordinator 只接受 `GET` 與 `HEAD`；公開的被動評估 API 只使用 `GET`。
- URL 會先正規化並移除查詢字串與 fragment，結果必須符合已保存的 Engagement Scope。
- Request header 只允許 `Accept` 與 `User-Agent`，拒絕憑證與 Cookie。
- 不跟隨 redirect，且拒絕 final target 改變。
- Timeout 限制為 1–60 秒。
- Response body 上限為 10 MiB，預設為 1 MiB。
- `HEAD` response 不得包含 body。
- 成功時，把 canonical request/response envelope 寫入持久化 Evidence chain。
- 傳輸失敗時，提交 `failed` Action，並把穩定且不洩漏細節的錯誤碼寫入稽核軌跡。

## 網路邊界

可選啟用的 `pinned-http/v1` transport 不使用環境 proxy，會在連線前解析主機名稱並驗證所有 DNS 回覆；它拒絕 denied network 與未明確允許的非公開位址，把選定 IP 固定到 socket，同時保留 HTTPS 對原始 hostname 的憑證與 SNI 驗證，不跟隨 redirect，並在讀取過程限制回應大小。

這是範圍刻意縮小的被動預覽 adapter，不是未來供 crawler、browser、第三方 scanner 或 active probe 使用的拋棄式 Worker runtime。後續能力仍須補上容器隔離、資源與 egress 限制、清理機制，以及獨立的執行生命週期監控。
