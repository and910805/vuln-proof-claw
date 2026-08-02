# Passive URL assessment 預覽版

**繁體中文** | [English](PASSIVE_ASSESSMENT.md)

0.0.11 版是第一條完整的 target-facing MVP 流程。輸入已授權 Engagement 內的 URL
後，系統會建立低風險 Action、執行一次有界 GET request、保存 tamper-evident
Evidence、產生保守的 Finding，並回傳既有 JSON 與 Markdown 報告連結。

這不是 autonomous penetration-testing engine。目前不會 crawl、提交 form、登入目標、
跟隨 redirect、傳送 payload 或呼叫外部資安工具。

## 啟用方式

應用程式層級預設仍停用。只綁定 loopback 的本機 Docker Compose profile 會啟用這條
有界路徑，讓首次使用流程可直接運作：

```text
VULN_PROOF_CLAW_ASSESSMENT__ENABLED=true
VULN_PROOF_CLAW_ASSESSMENT__TIMEOUT_SECONDS=10
VULN_PROOF_CLAW_ASSESSMENT__MAX_RESPONSE_BYTES=1048576
VULN_PROOF_CLAW_ASSESSMENT__USER_AGENT=vuln-proof-claw/0.1.0
```

Docker Compose 會把四個有界限的 assessment 設定傳入 container。若要關閉 target
traffic，可在 `.env` 設定 `VULN_PROOF_CLAW_ASSESSMENT__ENABLED=false`。尚未設定
正式環境 authentication 前，請維持只綁定 loopback。

正式環境若尚未達成 API authentication readiness，會拒絕啟用此設定。只有 operator
role 能啟動 assessment。URL 必須符合持久化 Engagement 的 hostname／CIDR、scheme、
port、path 與時間範圍。

## Web 控制台

開啟 `/#assessments`，輸入以 hostname 表示的 HTTP(S) URL、完成一次授權聲明後即可
啟動。聲明會保存在該瀏覽器，不必每次重新勾選。第一次執行會自動建立私有工作區；
Project 選擇仍可在進階整理選項內使用。

精靈會在背景建立只允許確切 hostname、scheme、port 與 path 的 24 小時 L0
Engagement。結果頁會顯示 Finding 明細、Action 終態、Evidence 數量與 chain 完整性，
並可下載目前的 JSON 或 Markdown Engagement report。

啟用 authentication 的 deployment 可透過「操作員權限」輸入 Operator Token。憑證只
保存在分頁範圍的 `sessionStorage`，也能在相同對話框清除。精靈不會自動替 IP literal
或 private target 建立 Scope；這類目標必須另外透過 API 建立經審查的 Engagement。

## Request

```http
POST /api/v1/engagements/{engagement_id}/assessments
Authorization: Bearer <operator token>
Idempotency-Key: baseline-homepage-1
Content-Type: application/json

{"target":"https://app.example.test/"}
```

Response 會包含 Action state、Evidence／Finding ID 與報告 URL。使用相同 key 與受保護
target 重送時會直接回傳持久化結果，不會再次送出 network request。同一 key 改用另一
target 時回覆 `409 idempotency_key_conflict`。可透過下列 endpoint 查詢持久化狀態：

```http
GET /api/v1/engagements/{engagement_id}/assessments/{action_id}
```

也可由新到舊查詢已保存的執行紀錄，而且不會產生 target traffic：

```http
GET /api/v1/assessments?project_id={project_id}&limit=50&offset=0
```

清單會提供正規化目標、terminal state 與時間、Evidence／Finding 數量、穩定錯誤碼及報告連結。省略 `project_id` 時會回傳跨專案歷史。

## Network control

- 連線前會查詢 system resolver，並驗證每一個 DNS answer。
- 回應中只要混入未預期 private、loopback、link-local、reserved 或 denied address，
  整個 request 都會遭拒絕。
- Private address 只有在 Engagement 明確允許其 CIDR 時才可使用。
- Socket 連線會固定選定 address；HTTPS certificate 與 SNI 仍使用原始 hostname 驗證。
- 不使用 environment proxy variable。
- Redirect 與 final-target change 會遭拒絕。
- 讀取 response 時即限制 byte 數；宣告過大的 `Content-Length` 會在讀取 body 前拒絕。

## Finding

Deterministic analyzer 目前檢查 cleartext HTTP、HSTS、`X-Content-Type-Options`、HTML
CSP／Referrer Policy、含版本的 Server header，以及名稱疑似敏感 Cookie 的
Secure／HttpOnly／SameSite flag。每筆 Finding 都會引用擷取到的 Evidence。這些檢查
刻意維持保守，不能取代人工驗證。

## 邁向 autonomous assessment 的剩餘工作

後續里程碑包括 container-isolated runtime、orphan cleanup、有界 crawl 與 endpoint
discovery、OpenAPI analysis、獨立 verifier、authenticated browser session，以及更完整
的 severity／remediation report contract。Active probe 與 exploit validation 仍需要
另外的 approval 與 safety design。
