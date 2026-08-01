# Authenticated Engine gateway client

**繁體中文** | [English](ENGINE_GATEWAY.md)

0.0.16 版實作控制平面連接未來 privileged Engine gateway 所使用的 client 與嚴格 wire
contract。它把受限 container policy 接到窄化 authenticated HTTP boundary，而且不會在
API process 掛載 Docker socket 或呼叫 Docker CLI。

## 連線政策

Gateway origin 與 token 必須一起設定。除 `127.0.0.1`、`::1` 等明確 loopback IP literal
外，一律要求 HTTPS；未加密 HTTP 的 `localhost` 會被拒絕，以避免 hosts file 與 DNS
歧義。Gateway URL 不得包含 credential、path、query 或 fragment，可選擇設定 private
CA bundle。

Bearer token 長度必須為 32–4096 個可見 ASCII 字元，而且不得與 API operator、approver 或
evidence-reader token 相同，並持續以 `SecretStr` 保存。Client 會停用 redirect follow
與環境 proxy discovery，避免 credential 被送往其他 origin 或環境中的 proxy。

## API contract

所有操作都透過 authenticated JSON 與版本化 `/v1` boundary：

- `POST /v1/health/ready`
- `POST /v1/containers/create`
- `POST /v1/containers/start`
- `POST /v1/containers/wait`
- `POST /v1/containers/stop`
- `POST /v1/containers/remove`
- `POST /v1/containers/inventory`

Container reference 維持為不透明 JSON value，不會進入 URL path。Create request 會重新
驗證 digest-pinned image、Worker UUID、非 root user、正值硬資源上限、固定
`cap_drop=ALL`、唯讀 root、`no-new-privileges`、必要 tmpfs path／option、完整
ownership label 與嚴格 `WorkerRequest` payload。Worker ID、request ID、container name、
label 與 protocol payload 必須完全一致。

## 有界 response

Response 會串流寫入有界 buffer，同時檢查宣告的 `Content-Length` 與實際串流 byte；
content type 必須是 JSON、未知 response field 會被拒絕，而且 base64 Worker output 在
解碼後還會再檢查一次。HTTP 與 transport detail 會轉換成穩定安全 code，例如：

- `engine_gateway_unauthorized`
- `engine_gateway_conflict`
- `engine_gateway_request_rejected`
- `engine_gateway_response_limit_exceeded`
- `engine_gateway_response_invalid`
- `engine_gateway_unavailable`

任何操作都不會自動 retry，因為 create／remove 的不確定狀態應透過不可變 ownership
inventory 解決，而不是盲目重送。

## 目前邊界

Client、configuration gate、readiness contract、wire schema、有界 transport，以及與
`DockerWorkerRuntime` 的整合皆已完成並測試。持有 Engine credential 的獨立 gateway
server、scope egress enforcement、Worker-side executor、application startup wiring 與
隔離 target fixture 仍待完成。因此 Compose 的 `RUNTIME_ENABLED` 仍為 false，本版不會
啟用新的面向目標工具執行。
