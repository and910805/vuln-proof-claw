# Worker Capture 匯入

**繁體中文** | [English](WORKER_CAPTURE_INGESTION.md)

0.0.20 版新增不受信任的拋棄式 Worker response 與控制面 Evidence chain 之間的可信
匯入邊界。本版不會啟用 Worker 網路執行。

## Inline 契約

成功的 Worker 可以回傳一筆 `http-v1` capture，取代 Evidence ID。Capture 僅允許
GET 或 HEAD、canonical request／final target、allowlist 內的 request header、有界
response header、一份解碼後最多 512 KiB 的 body、body SHA-256 digest、具時區的
capture timestamp 與有界 duration。Redirect、HEAD body、無效 base64、digest 不符、
inline capture 與 Evidence ID 混用，以及時間落在 Worker response window 外，都會在
協定層被拒絕。

Raw capture 不會出現在物件 representation。Docker、Engine gateway 與 Worker output
上限仍是彼此獨立的外層限制。

## 可信重驗證與持久化

控制面不信任 Worker 提供的 target、timestamp、method、header、duration 或 digest。
寫入前會：

1. 將 capture target 與 duration 綁定原始 Worker request；
2. 重建受保護的 `HttpCaptureRequest` 並核對 Action parameter digest；
3. 以 capture timestamp 對持久化 Engagement scope 重新評估 canonical target；
4. 重建既有 `HttpCaptureResponse`，包含 redirect 與 HEAD-body 規則；
5. 由控制面產生 Evidence ID，並將 canonical raw capture 交易式加入每個 Engagement 的
   hash chain；
6. 回傳只含新 Evidence ID 的正規化終止 response。

任何 binding 或 scope 失敗都會以穩定安全錯誤將 Action 關閉為 failed，且不寫入
Evidence。Audit event 只包含 Evidence ID、狀態與安全錯誤碼，不包含 inline body。

## 0.0.21 後續進度

0.0.21 新增 [WORKER_HTTP_EXECUTOR.zh-TW.md](WORKER_HTTP_EXECUTOR.zh-TW.md) 所述、
經窄範圍審查且不使用憑證的 GET／HEAD executor。因此 ingestion path 已能在明確開放
網路且受 Scope 約束的環境接收真實 capture。官方 Docker Worker network 仍為 internal；
受控 container egress 與啟動整合仍待完成。
