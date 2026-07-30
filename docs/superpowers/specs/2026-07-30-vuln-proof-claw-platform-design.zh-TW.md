# vuln-proof-claw 平台設計

[English](2026-07-30-vuln-proof-claw-platform-design.md) | **繁體中文**

**狀態：** 已核准

**日期：** 2026-07-30

**預設分支：** `mainer`

**授權：** MIT

## 1. 執行摘要

vuln-proof-claw 是一套以證據為核心的自主式 Web 與 API 安全測試平台，服務對象包括已取得授權的企業資安團隊、紅隊、滲透測試人員與漏洞研究人員。

本專案採獨立實作，可吸收 VulnClaw 與 PentAGI 的架構思想，但不會成為任一專案的 fork。若重用任何 MIT 授權程式碼，必須保留適用的著作權與授權聲明。

已核准的交付路線為：

> 以 Docker Compose 作為核心部署方式，以本機 CLI 作為第一個使用者介面，待核心工作流程穩定後再加入 React Web UI。

第一階段聚焦 Web/API 安全測試與基礎網路偵察。後續階段可加入內網、Active Directory、雲端、行動裝置、分散式 Worker 與多人協作。

### 1.1 命名規範

- 倉庫與發行名稱：`vuln-proof-claw`
- CLI 命令：`vuln-proof-claw`
- Python import 套件：`vuln_proof_claw`
- Docker image 前綴：`vuln-proof-claw`
- 環境變數前綴：`VULN_PROOF_CLAW_`

## 2. 產品定位

### 2.1 目標使用者

- 驗證產品與內部服務的企業資安工程師。
- 執行授權專案的紅隊與滲透測試公司。
- 需要可重現證據以提交報告的漏洞研究員與 Bug Bounty Hunter。

### 2.2 核心價值

vuln-proof-claw 的目標不是產生大量推測性漏洞，而是產生可追溯至真實動作與證據的 finding：

- 每個已驗證 finding 都引用持久化證據。
- 每個動作都必須符合明確的 Engagement scope。
- 高風險動作必須取得批准。
- 所有接觸目標的工具都在隔離且可拋棄的 Worker 中執行。
- Finding 必須可重現或經獨立驗證。

### 2.3 產品原則

1. **證據優先：** 沒有原始證據就不能成為已驗證 finding。
2. **先判定範圍再執行：** Scope 必須由程式碼強制執行，不能只寫在 prompt。
3. **依風險批准：** 動作分為 L0 至 L4。
4. **預設隔離：** 目標端工具在拋棄式 Docker Worker 中執行。
5. **模型獨立：** 領域模型與工作流程不依賴單一 LLM Provider。
6. **結果可重現：** 已驗證 finding 必須包含可重播請求或等效驗證步驟。
7. **人類保有權限：** Agent 可以提議動作，但使用者與 Policy Engine 擁有最終決定權。
8. **專案隔離：** 不同 Project 的記憶與證據預設不互通。

## 3. 範圍與 Roadmap 邊界

### 3.1 第一階段範圍

第一階段包含：

- Web 應用安全測試。
- HTTP 與 API 安全測試。
- 基礎網路偵察。
- CLI 與 REST API。
- Docker Compose 部署。
- PostgreSQL 持久化。
- 拋棄式 Docker Worker。
- 多 LLM Provider 支援。
- Planner、Operator、Verifier 三種 Agent。
- Scope、批准、Policy 與 audit 工作流程。
- Evidence hash chain。
- 結構化 finding 與報告。
- 穩定的工具／插件介面。

### 3.2 第一階段暫不包含

- React Web UI。
- 多租戶組織與帳號管理。
- Active Directory 測試。
- 內網橫向移動工具。
- 雲端與行動裝置安全測試。
- 分散式遠端 Worker。
- 插件市集與公共 Registry。
- 跨專案全域記憶。
- 完整 Burp Professional 整合。

### 3.3 長期 Roadmap

- **v0.4：** React/TypeScript Web UI。
- **v1.0：** 穩定 API、Plugin SDK、簽章發布與正式文件。
- **v2+：** 內網、Active Directory、雲端、行動裝置、團隊、分散式 Worker 與插件 Registry。

## 4. 系統架構

vuln-proof-claw 使用 Python 模組化單體作為控制面，並使用可拋棄 Docker 容器作為執行面。

```text
┌───────────────────────────────────────────────┐
│                   使用者介面                  │
│       CLI 優先 │ REST API │ 後續 Web UI       │
└───────────────────────┬───────────────────────┘
                        │
┌───────────────────────▼───────────────────────┐
│            vuln-proof-claw 控制面             │
│                                               │
│ Project & Scope    Flow / Task / Action        │
│ Approval Policy    Agent Orchestrator          │
│ Evidence Catalog   Finding Verification        │
│ Report Generator   Provider Adapters           │
└───────────────┬─────────────────┬─────────────┘
                │                 │
        ┌───────▼──────┐   ┌──────▼───────────┐
        │ PostgreSQL   │   │ Worker Manager   │
        │ 狀態／索引   │   │ 生命週期／政策  │
        └──────────────┘   └──────┬───────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ 拋棄式 Docker Worker      │
                    │                           │
                    │ HTTP/Proxy │ Browser      │
                    │ Web Tools  │ Shell        │
                    │ Evidence Collector        │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ 已授權的 Web/API 目標     │
                    └───────────────────────────┘
```

### 4.1 初始技術選擇

- Python 3.12 或更新版本。
- FastAPI 作為 REST 控制面。
- Typer 作為 CLI。
- Pydantic 作為 schema 與設定模型。
- SQLAlchemy 2 與 Alembic。
- PostgreSQL。
- Docker SDK 管理 Worker 生命週期。
- HTTPX 執行結構化 HTTP 動作。
- Playwright 執行隔離瀏覽器自動化。
- pytest、Ruff，以及 mypy 或 Pyright。
- 自 v0.4 起加入 React 與 TypeScript。

### 4.2 模組邊界

```text
vuln_proof_claw/
├── api/              # REST API
├── cli/              # CLI 與 API client
├── domain/           # Project、Flow、Action、Finding、Evidence
├── orchestration/    # Agent 與工作流程協調
├── policy/           # Scope、風險、批准、audit
├── execution/        # Worker 生命週期與執行協定
├── evidence/         # 證據儲存、hash、redaction
├── providers/        # LLM Provider adapter 與 preset
├── tools/            # 結構化 Web/API 工具
├── reporting/        # Markdown、JSON、HTML、SARIF
└── persistence/      # PostgreSQL repository 與 migration
```

第一階段的這些項目是模組邊界，而不是獨立部署的微服務。只有在實際營運需求出現時，才拆分 Worker Manager 或 Agent Orchestrator。

### 4.3 初始 Docker Compose 拓撲

- `vuln-proof-claw-api`
- `vuln-proof-claw-postgres`
- `vuln-proof-claw-worker-manager`
- 由 Worker Manager 為每個 Flow 建立的拋棄式 Worker

Redis、Neo4j、MinIO、Grafana 等服務不列為基礎依賴，只有在量測後確認需求時才加入。

## 5. 領域與證據模型

### 5.1 實體階層

```text
Project
└── Engagement
    └── Flow
        └── Task
            └── Action
                ├── Tool Call
                ├── Evidence
                └── Artifact
```

- **Project：** 客戶、產品或研究專案。
- **Engagement：** 具有期限與明確 scope 的安全測試活動。
- **Flow：** Engagement 中的一個完整測試目標。
- **Task：** 經規劃且可執行的工作單位。
- **Action：** Agent 或使用者提出的具體操作。
- **Evidence：** 與 Action 關聯且不可任意修改的原始輸出。
- **Artifact：** 截圖、HAR、PoC、下載檔案或產生的報告。

### 5.2 Evidence 要求

每筆 Evidence 包含：

- Evidence ID 與 Action ID。
- 工具名稱與版本。
- 正規化後的輸入參數。
- 原始輸出。
- 適用時保存 HTTP Request 與 Response。
- 執行時間與持續時間。
- Worker image 與環境 metadata。
- Scope Policy 判定。
- 需要批准時保存 Approval ID。
- SHA-256 digest。
- 前一筆 Evidence digest。

初始防竄改鏈為：

```text
evidence_hash = SHA256(previous_hash + canonical_metadata + raw_content)
```

第一階段不宣稱具備數位鑑識等級的不可否認性，但必須提供確定性的完整性驗證與修改偵測。

### 5.3 Finding 生命週期

```text
candidate
    ↓
pending_verification
    ├── verified
    ├── rejected
    └── needs_manual_review
```

只有 Verifier 能將 finding 提升為 `verified`。必須滿足：

- 至少一筆有效 Evidence。
- 明確受影響的 target、endpoint，以及 parameter 或 component。
- 可觀察的安全影響。
- 可重播或經獨立驗證的行為。
- Action 符合 scope 且具備必要批准。
- Evidence hash chain 驗證成功。

已驗證 finding 包含：

- 標題、漏洞類型、嚴重度、CWE 與可選 CVSS。
- 受影響的資產與 endpoint。
- 技術說明與影響。
- 重現步驟。
- 經 redaction 的 HTTP Request 與 Response。
- Evidence 引用。
- PoC 或 replay 定義。
- 修補建議。
- 驗證狀態與信心水準。

報告 redaction 不得修改儲存的原始 Evidence。

## 6. Scope、風險與批准政策

### 6.1 Engagement scope

Engagement 可定義：

- 允許的 hostname、IP 與 CIDR。
- 允許的 port。
- 允許與禁止的 URL path。
- 測試開始與結束時間。
- 核准的身分與測試帳號。
- 最高 Action level。
- Request rate 與 concurrency limit。
- 排除的第三方系統。
- 授權參考與備註。

### 6.2 強制流程

```text
Agent 提出 Action
        ↓
正規化 target 與參數
        ↓
Scope Policy Check
        ↓
Risk Classification
        ↓
Automatic / Approval / Denied
        ↓
Worker 執行
```

Policy 優先順序：

```text
系統永久禁止規則
    > Engagement 禁止規則
    > Engagement 允許規則
    > 使用者單次批准
    > Agent 提議
```

### 6.3 風險等級

| 等級 | 範例 | 預設行為 |
|---|---|---|
| L0 | 公開頁面、`robots.txt`、被動指紋辨識 | 自動 |
| L1 | 目錄枚舉、nmap、主動 API 探測 | 由 Project 設定 |
| L2 | Exploit payload、密碼測試、檔案上傳 | 必須批准 |
| L3 | 後滲透、權限提升、橫向移動 | 必須批准 |
| L4 | 資料修改／刪除、持久化、破壞性操作 | 預設停用；必須明確開啟並逐次批准 |

Approval 必須綁定：

- Engagement。
- Action type。
- 正規化 target。
- 參數摘要與 digest。
- 風險等級。
- 到期時間。
- 可執行次數。
- 批准者與批准時間。

修改 payload、target 或受保護參數後，原 Approval 立即失效。

### 6.4 Worker 安全基準

Worker 預設：

- 使用非 root 使用者。
- 在可行時使用唯讀 root filesystem。
- 限制 CPU、記憶體、PID 與執行時間。
- 不掛載 Docker socket。
- 不掛載主機 home directory 或 credential store。
- 只掛載單次 Flow 的 task directory。
- 將 network egress 限制在 Engagement scope。
- 不直接取得控制面的 LLM credential。
- 完成後銷毀。

Redirect、DNS 解析、proxy、IPv4/IPv6 正規化與瀏覽器子資源都必須在執行邊界再次檢查。

目標回傳的 HTML、JavaScript、API response、檔案與工具輸出都屬於不可信資料，不能授予工具權限或繞過 Policy。

## 7. Agent 工作流程

### 7.1 Planner

Planner：

- 理解使用者目標與 Engagement scope。
- 建立、排序與更新結構化 Task。
- 在 Evidence 改變假設時重新規劃。
- 判斷 Flow 是否完成、受阻或等待批准。
- 不執行目標端工具。

### 7.2 Operator

Operator：

- 選擇工具。
- 產生結構化 Action Proposal。
- 根據工具 Evidence 選擇後續 Action。
- 建立 candidate finding。
- 不能批准 Action。
- 不能將 finding 標記為 verified。

### 7.3 Verifier

Verifier：

- 依持久化 Evidence 審查 candidate claim。
- 可提出 scope 內的獨立驗證 Action。
- 偵測 same-body response、誤報、錯誤狀態碼假設與缺乏證據的模型結論。
- 指派 `verified`、`rejected` 或 `needs_manual_review`。
- 產生最小重現步驟。

Verifier 只取得 candidate claim、Engagement scope 與引用 Evidence，不直接繼承 Operator 的結論，並可使用不同 Provider 或模型。

### 7.4 執行循環

```text
User Goal
    ↓
Planner 建立 Tasks
    ↓
Operator 提出 Action
    ↓
Policy Engine
    ├── denied ─────→ 記錄並重新規劃
    ├── approval ───→ 暫停並詢問使用者
    └── allowed ────→ Worker Execution
                           ↓
                       Evidence
                           ↓
              ┌────────────┴────────────┐
              │                         │
        繼續 Task                  Candidate Finding
              │                         ↓
              └──────────────────→ Verifier
                                        ↓
                     verified / rejected / manual review
```

### 7.5 記憶

- **Execution context：** 近期訊息與有界的工具結果預覽。
- **Evidence store：** 不因 context 壓縮而遺失的完整原始輸出。
- **Project memory：** 已驗證的資產、endpoint、技術與 finding。

大型 body 與 log 保存在 Evidence storage。Agent 使用高訊號摘要與 Evidence ID，需要時再搜尋或分頁讀取原始內容。

## 8. LLM Provider 架構

第一階段建立 Provider Registry，而不是單一 Provider 實作。

支援的 Provider family：

- OpenAI。
- Anthropic。
- Google Gemini。
- Azure OpenAI。
- AWS Bedrock。
- Ollama。
- OpenRouter。
- OpenAI-compatible endpoint。
- DeepSeek、Kimi/Moonshot、Qwen、MiniMax、GLM、SiliconFlow 等相容服務的 preset。
- Custom Provider。

統一 Provider interface：

```text
generate()
stream()
tool_call()
count_tokens()
estimate_cost()
capability_check()
```

必要行為：

- 每個 Agent 可獨立選擇 Provider 與 model。
- Provider capability detection。
- 缺少原生 tool calling 時使用結構化 JSON fallback。
- Timeout、retry、rate limit 與 failover。
- Flow 層級 token 與費用預算。
- Ollama 完全本機模式。
- Project policy 可禁止外部雲端 Provider。
- 將受保護資料送往遠端 Provider 前先執行 redaction。

Failover 不得導致已提交的目標端 Action 重複執行。

## 9. 工具與插件

### 9.1 第一階段結構化工具

- `http_request`
- `http_batch`
- `http_replay`
- `traffic_list`
- `traffic_search`
- `traffic_view`
- `traffic_sitemap`
- `web_crawl`
- `dir_enumerate`
- `api_discover`
- `openapi_analyze`
- `graphql_analyze`
- `auth_differential`
- `browser_navigate`
- `browser_capture`
- `tech_fingerprint`
- `network_scan`
- `dns_resolve`
- `encode_decode`
- `evidence_search`
- `evidence_view`
- `source_extract`
- `restricted_shell`
- 在隔離環境中、依 capability 控制的 Python execution

每個工具宣告：

- Input 與 output JSON schema。
- 固定風險等級或確定性的分類函式。
- Network 與 target mutation 行為。
- 必要 Worker capability。
- Timeout 與資源限制。
- Evidence serializer。
- Redaction 規則。
- Scope validator。

### 9.2 Plugin contract

```python
class ProofClawTool:
    manifest: ToolManifest

    async def validate(self, action, scope): ...
    async def execute(self, context): ...
    async def collect_evidence(self, result): ...
```

Manifest 包含 name、version、author、license、permission、risk metadata、capability 與 input/output schema。

第一階段只支援本機安裝且受信任的插件。第三方簽章套件、遠端 Registry 與 marketplace 延後處理。

### 9.3 Web/API Playbook

初始精選 Playbook：

- Web reconnaissance。
- API discovery。
- Authentication 與 session testing。
- Authorization 與 IDOR。
- Injection testing。
- SSRF、XXE 與 file handling。
- Business logic testing。
- Evidence verification。
- Bug bounty reporting。
- Remediation guidance。

Playbook 是參考資料，不能授予 capability 或繞過 Policy。

## 10. 報告

第一階段輸出：

- Markdown。
- JSON。
- HTML。
- SARIF。
- Bug bounty submission format。
- Machine-readable Evidence Manifest。

報告包含：

- 提供風險與修補優先順序的 Executive Summary。
- 包含重現步驟、Request、Response、PoC、Evidence ID 與 hash 的技術證據。

匯出 redaction 必須處理 authorization header、cookie、API key、session token、個資與使用者設定的敏感欄位。

PDF 延後至 Web UI 階段，並由 HTML representation 產生。

## 11. 與 VulnClaw 第一階段比較

vuln-proof-claw 第一階段必須達到 VulnClaw 的實用 Web/API 基準，並提升隔離、Policy enforcement、Evidence integrity、獨立驗證與報告格式。

| 能力 | VulnClaw 基準 | vuln-proof-claw 第一階段目標 |
|---|---|---|
| 自主工作流程 | 模型主導 solve loop | Planner、Operator、Verifier |
| CLI | CLI、REPL、TUI | CLI 優先；v0.3 評估 REPL |
| Web UI | 已提供 | 延後至 v0.4 |
| 部署 | 主要為單一應用容器 | 控制面、PostgreSQL、拋棄式 Worker |
| Provider | 多種 preset | 原生 Provider family 與 compatible preset |
| HTTP 與 batch probing | 已提供 | 結構化 request、batch、evidence、replay |
| Traffic evidence | 原始流量檔案與索引 | 持久化 Evidence 與 hash chain |
| Reconnaissance | 目錄、JS、nmap、auth check | 對等的 Web/API 結構化工具 |
| Browser | 外部 Chrome MCP | 隔離 Playwright；MCP 可選 |
| Shell 與 Python | 內建實驗性能力 | 隔離且依 capability 控制 |
| Skill | 廣泛安全與 CTF 集合 | 第一階段精選 Web/API Playbook |
| 反幻覺 | Evidence completion gate | 獨立 Verifier 與 finding lifecycle |
| Scope | Host/path/port 與 action check | 具 scope awareness 的 network execution boundary |
| Approval | Task constraint | 綁定 Action 的 L0-L4 Approval |
| Reporting | Markdown 與 PoC | Markdown、JSON、HTML、SARIF、bug bounty |

第一階段刻意延後不符合 Web/API 定位的廣度，包括 TUI、內網知識包、Android／逆向內容與極長 persistent loop。

## 12. Action 可靠性與錯誤處理

### 12.1 Action 狀態

```text
proposed
    ↓
policy_check
    ├── denied
    ├── pending_approval
    └── queued
          ↓
       running
          ├── succeeded
          ├── failed
          ├── timed_out
          ├── cancelled
          └── worker_lost
```

### 12.2 可靠性規則

- 每個 Action 都有 idempotency key。
- 讀取型 L0/L1 Action 可依 Policy retry。
- L2-L4 Action 不自動 retry。
- LLM failover 不能重複執行目標端 Action。
- Worker failure 必須保存已取得的 stdout、stderr、traffic 與 Evidence。
- 報告只能引用已持久化 Evidence。
- Flow 具備 time、step、token、cost、request 與 failure budget。
- 使用者可暫停、恢復與取消 Flow。
- Denial、approval、retry、cancellation 與 Policy decision 都必須 audit。

## 13. 測試策略

### 13.1 Unit test

- Scope normalization。
- L0-L4 classification。
- Approval binding 與 replay prevention。
- Evidence hash-chain validation。
- Finding lifecycle。
- Redaction。

### 13.2 Contract test

- LLM Provider adapter。
- Tool 與 plugin schema。
- Worker protocol。
- Report serializer。

### 13.3 Integration test

- PostgreSQL migration。
- Worker 建立與銷毀。
- API 至 Action 至 Evidence 的完整流程。
- Timeout、cancellation 與 Worker crash recovery。

### 13.4 Security test

- Redirect scope escape。
- DNS rebinding。
- IPv4 與 IPv6 normalization bypass。
- 來自目標內容的 prompt injection。
- Shell argument injection。
- Path traversal。
- Secret redaction。
- Approval replay 與 parameter mutation。

### 13.5 End-to-end lab test

主動測試只能在隔離 CI network 中對刻意存在漏洞的本機目標執行，例如：

- OWASP Juice Shop。
- crAPI。
- WebGoat。
- 為測試建立的最小服務。

CI 不得對公共網站執行主動測試。

### 13.6 CI quality gate

- Ruff。
- mypy 或 Pyright。
- pytest 與 coverage。
- pip-audit。
- Bandit。
- CodeQL。
- Trivy。
- Secret scanning。
- Docker image build。
- SBOM generation。

## 14. 開源治理

倉庫將包含：

- `README.md`
- `README.zh-TW.md`
- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `GOVERNANCE.md`
- `CHANGELOG.md`
- `ROADMAP.md`
- `THREAT_MODEL.md`
- `ARCHITECTURE.md`
- Issue 與 Pull Request template。
- Dependabot 設定。
- Release automation。
- Developer Certificate of Origin policy。
- Third-party notice。

### 14.1 雙語文件政策

- 每份持續維護的專案文件都必須同時提供英文與繁體中文。
- 英文文件使用基礎檔名，例如 `README.md` 或 `ARCHITECTURE.md`。
- 繁體中文文件使用 `.zh-TW.md` 後綴，例如 `README.zh-TW.md` 或 `ARCHITECTURE.zh-TW.md`。
- 每個語言版本都要在文件頂部附近連結至另一個版本。
- 兩個版本必須具有相同的需求、版本狀態與技術含義。
- 修改任一語言版本的 Pull Request 必須同步更新配對文件，或在 merge 前明確標記翻譯仍待完成。
- 程式碼 identifier、command name、API field 與 configuration key 不翻譯。

專案採 MIT License。VulnClaw 與 PentAGI 將列於 Acknowledgements。若重用程式碼，必須保留原始聲明。

## 15. 交付里程碑

### Phase 0 — Foundation

- Repository 與 module structure。
- Docker Compose。
- FastAPI、CLI 與 PostgreSQL。
- Migration、configuration 與 structured logging。
- CI 與開源治理文件。

### v0.1 — Evidence Core

- Project、Engagement 與 Scope。
- Worker lifecycle。
- HTTP request 與 response 工具。
- Action state machine。
- Evidence hash chain。
- 初始 Markdown 與 JSON report。

### v0.2 — Autonomous Core

- Planner、Operator 與 Verifier。
- Multi-provider Registry。
- Approval workflow。
- Execution context 與 Evidence memory。
- Flow budget 與 stopping condition。

### v0.3 — Web/API Parity

- Crawler 與 directory enumeration。
- JavaScript、OpenAPI 與 GraphQL discovery。
- Authentication differential testing。
- Browser 與基礎 nmap 整合。
- Restricted shell 與 Python。
- Web/API Playbook。
- HTML、SARIF 與 bug bounty report。

v0.3 必須達到選定的 VulnClaw Web/API 基準，並證明在隔離、Policy enforcement、Evidence integrity、驗證與報告方面的提升。

### v0.4 — Web Experience

- React 與 TypeScript UI。
- 即時 Flow view。
- Approval inbox。
- Evidence viewer。
- Finding review。
- Report preview。

### v1.0 — 穩定開源版本

- 穩定 REST API。
- Tool Plugin SDK。
- Upgrade 與 migration 文件。
- Security review。
- Performance 與 recovery test。
- 發布 image、SBOM 與 signature。

## 16. 第一階段驗收條件

第一階段完成時必須符合：

1. 使用者可透過 Docker Compose 啟動 vuln-proof-claw，並使用 CLI 操作。
2. 沒有明確 scope 就不能開始 Engagement。
3. 所有目標端 Action 都在拋棄式 Worker 中執行。
4. 超出 scope 的 DNS、redirect、browser 與 HTTP traffic 必須在執行時遭阻擋。
5. L2-L4 Action 未取得必要 Approval 時不能執行。
6. 受保護的 Action parameter 變更後，Approval 不得重用。
7. 每個 Tool result 都產生可驗證的 Evidence record。
8. 只有 Verifier 能提升 candidate finding。
9. Verified finding 可由儲存 Evidence 或 replay definition 重現。
10. 匯出報告不能覆寫原始 Evidence。
11. 選定的多 Provider family 必須通過 contract test。
12. 主動 E2E test 只能對隔離本機目標執行。
13. v0.3 Web/API capability 必須達到文件記載的 VulnClaw 比較基準。

## 17. 明確非目標

- 協助未授權測試。
- 將 prompt 視為安全邊界。
- 在第一階段宣稱具備鑑識不可否認性。
- 在出現可量測的擴充需求前建立微服務平台。
- 將 Agent 數量最大化視為產品特色。
- 允許不可信目標內容授予 capability。
- 自動 retry 高風險 Action。
