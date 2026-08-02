# Worker HTTP Executor

**繁體中文** | [English](WORKER_HTTP_EXECUTOR.md)

0.0.21 版為拋棄式 Worker 新增一項刻意收窄的目標連線能力：僅能針對
`public_page_read` L0 Action，執行受 Scope 約束、無憑證的 HTTP GET 或 HEAD。
這是蒐集證據的基礎元件，不是自動滲透引擎。

## Request 契約

控制平面送出 `WorkerHttpAction`，內容包含 method、canonical target、allowlist
內的 request header，以及解碼後 response 上限。Worker 僅接受：

- 不含 request body 的 `GET` 或 `HEAD`；
- 既有的安全 request-header allowlist，不接受 Authorization、Cookie、proxy
  credential 或其他環境憑證；
- 最長 60 秒的 timeout；以及
- 1 byte 至 512 KiB 的解碼後 response body 上限。

Request 必須具備 `http_client` capability，且 parameter digest 必須由 method、
canonical target 與 headers 重新計算一致。欄位缺失、不支援或產生 drift 時，
一律在網路 I/O 前 fail closed。

## 網路與 Response 防護

Executor 重用 DNS-pinned transport。它不使用 proxy，先解析全部候選位址，且只有
在每個候選位址均為公開可路由位址，或明確落在 Engagement 允許的 CIDR 時才繼續；
因此混合公開／私有位址的 DNS 回覆也會被拒絕。連線會固定到一個已驗證的 IP，
HTTPS 憑證仍以原始 hostname 驗證，且不跟隨 redirect。

宣告的長度與實際串流大小分別受限。HEAD response 不得帶有 body，實測 duration
也不得超過核准 timeout。預期失敗只回傳穩定 error code；未知 transport 或 exception
細節不會反射給呼叫端。

## Evidence Pipeline

成功時，Worker 回傳一份 inline `http-v1` capture，且不自行產生 Evidence ID。
可信任的控制平面會重新驗證 Action digest、target、duration、持久化且具時間條件的
Scope、response 語意、解碼後大小與 body SHA-256。只有控制平面能配置 Evidence ID，
並把 canonical content 寫入 Engagement hash chain；lifecycle response 僅暴露
Evidence ID，不暴露 inline body。

整合測試使用明確允許的 loopback server，驗證 Worker request、DNS-pinned capture、
可信匯入、Evidence ID 配置、Action 完成，以及 hash chain 驗證的完整路徑。

## Runtime 邊界與待辦

官方 Docker Worker network 仍維持 `internal: true`。這可保留已審查的 fail-closed
runtime，也代表目前官方 container 尚無法連線公開目標。仍須完成受控 container
egress、production startup wiring 與 registry 發布的 image digest，才能在官方部署
路徑啟用此能力。

POST、憑證、登入 session、JavaScript、crawler、browser automation、exploit payload
與任意工具都不在此版本契約內。
