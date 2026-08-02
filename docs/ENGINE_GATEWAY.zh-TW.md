# 已驗證的 Engine gateway 邊界

**繁體中文** | [English](ENGINE_GATEWAY.md)

0.0.17 版完成控制平面與獨立高權限 Engine process 之間的窄版 HTTP 邊界。API
process 不掛載 Engine socket，也不呼叫 container CLI。

## 信任邊界

Client 僅接受 HTTPS origin；本機開發則可使用明確的 loopback IP literal。URL 不得含
credential、path、query 或 fragment，並停用 redirect 與環境 proxy 探測。兩個 process
必須使用相同的 32–4096 字元 Bearer secret，而且不得與任何 API role token 相同。

Server 預設關閉，沒有明確 enable 與 token 就拒絕建立；OpenAPI 與互動文件端點也已
關閉。0.0.17 尚未包含真正的高權限 backend，因此未注入 backend 時會刻意保持
unready，只回傳安全的 unavailable code。

## 版本化生命週期契約

所有操作都透過 `/v1` 的 authenticated JSON：

- `POST /v1/health/ready`
- `POST /v1/containers/create`
- `POST /v1/containers/start`
- `POST /v1/containers/wait`
- `POST /v1/containers/stop`
- `POST /v1/containers/remove`
- `POST /v1/containers/inventory`

Container reference 僅作為不透明 JSON value，不進入 URL path。Create request 會獨立
重驗 digest-pinned image、Worker/name/request 身分、非 root user、固定權限限制、資源
上限、tmpfs policy、ownership labels 與嚴格 Worker protocol payload。

## Server 防護

Authentication 會在解析 request 或取得 backend admission 之前執行。宣告的
`Content-Length` 與實際串流 bytes 都會先受限，再進行 strict JSON validation；未知欄位
一律拒絕。Semaphore 限制高權限操作併發數，排隊也有短 timeout。Worker output 在編碼
前會再次檢查大小。

Backend 的 busy、conflict、not found、rejected 與 unavailable 狀態會映射成穩定 code。
未預期 exception 文字、daemon path、credential 與 response body 都不會穿越邊界。
Mutating operation 不會被盲目 retry。

Listener 必須以獨立 process 啟動：

```console
vuln-proof-claw-engine
```

必要環境變數記錄於 `.env.example`。在 reviewed backend、transport protection 與部署隔離
完成前，請維持 `VULN_PROOF_CLAW_ENGINE_SERVER__ENABLED=false`。

## 目前範圍

Client、server、共享 schema、authentication、request/response bounds、admission
control、安全 error mapping、設定 gate 與記憶體內端到端契約均已完成並測試。Engine
adapter、受 Scope 約束的 egress、Worker-side executor、startup integration 與隔離 target
fixture 留待後續版本，因此 Compose runtime 仍預設關閉。
