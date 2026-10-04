# 自主代理架構

本文件說明如何將 ProofClaw 從「請求驅動的評估控制平面」遷移為一套
**持續性、具狀態、以證據驅動的自主資安研究代理**，用於明確獲得授權的漏洞懸賞委託。

這是一份遷移計畫，不是重寫。所有既有的安全控制都被保留並重複使用；
自主層建立在它們**之上**，且在結構上無法繞過它們。

---

## 1. 不可妥協的不變條件

以下條件適用於每一個階段。削弱其中任何一項都是缺陷，而非取捨。

1. **先有證據，才有主張。** `Finding` 只能由 Verifier 從可重現的證據產生。
   掃描器與啟發式規則只能產生 `Candidate`，永遠不能直接產生 Finding。
2. **絕不超出授權範圍。** 每個面向目標的操作都必須通過
   `policy.scope.evaluate_scope()`。範圍採預設拒絕、拒絕優先於允許。
3. **代理不能自我核准。** L2/L3 需要人工核准紀錄，且綁定到完全一致的
   `(action_type, normalized_target, parameter_digest, risk_level)`。
4. **代理不能重新分類風險。** `policy.risk.classify_risk()` 是以 `action_type`
   為鍵的靜態表；`decide_action()` 會以 `risk_classification_mismatch` 拒絕。
   提出行動的 LLM 無法自行選擇風險等級。
5. **L4 永遠拒絕。** 沒有任何設定路徑能讓自主執行進行破壞性操作。
6. **不做規避。** 破解 CAPTCHA、繞過 WAF、規避機器人偵測在設計上即排除，
   而非遺漏。遇到這些控制是**停止**訊號。
7. **所有行動可稽核。** `audit_events` 記錄每一次控制平面轉換的決策、
   執行者與正規化酬載。
8. **沒有新證據就不重試失敗的假說。** 由 Lead 冷卻規則以決定性邏輯強制執行，
   而非交由 LLM 判斷。

---

## 2. 既有且重複使用的元件（不取代）

本儲存庫已經實作了大部分困難的安全機制。自主層是它們的使用者，而非同級元件。

| 能力 | 模組 | 狀態 |
|---|---|---|
| 預設拒絕範圍引擎 | `policy/scope.py` | 重用；擴充萬用字元網域 |
| 決定性 L0–L4 風險表 | `policy/risk.py` | 原樣重用 |
| 政策決策（範圍+風險+核准） | `policy/decision.py:decide_action` | 原樣重用 |
| 一次性綁定核准 | `policy/approval.py`, `domain/models.py:Approval` | 原樣重用 |
| 執行授權唯一關卡 | `execution/authorization.py` | 原樣重用 |
| 可拋棄式 worker 生命週期 | `execution/lifecycle.py`, `execution/manager.py` | 重用 |
| 容器隔離（唯讀、cap-drop ALL、內部網路、非 root、digest 釘選） | `execution/docker_runtime.py`, `engine/docker_backend.py` | 重用 |
| DNS 釘選外連 + SSRF 防護 | `execution/pinned_http.py` | 重用 |
| 證據雜湊鏈 | `evidence/hash_chain.py`, `evidence/persistence.py` | 重用 |
| Planner/Operator/Verifier 步驟機 | `automation/autonomy.py` | 作為循環核心重用 |
| 工具註冊表與型別化契約 | `tooling/registry.py`, `tooling/contracts.py` | 依階段擴充 |
| 稽核事件 | `audit.py` | 重用 |
| 被動探索 / OpenAPI 解析 | `assessment/` | 由偵察循環重用 |

**關鍵結構性事實：** `execution/authorization.py:authorize_queued_action()` 會在執行前
立即以資料庫中的即時範圍重新執行 `decide_action()`。因此即使自主控制器自身的記憶體
狀態損毀，或 LLM 回傳惡意輸出，控制器也無法經由任何跳過政策的路徑執行行動。

---

## 3. 缺口分析

自主代理所需、但目前不存在的能力：

| 缺口 | 對應階段 |
|---|---|
| 沒有持續循環；一切都是請求驅動 | 階段 1 — Mission Controller |
| 掃描器輸出與 Finding 之間沒有假說物件 | 階段 1 — Lead |
| 沒有資產/端點盤點或研究記憶 | 階段 1 — 知識庫 |
| 沒有排程節奏或冷卻邏輯 | 階段 1 — Scheduler |
| 沒有速率限制、請求預算或 token 預算 | 階段 1 — 預算帳本 |
| 沒有攻擊面快照與變更偵測 | 階段 1（核心）/ 階段 6（完整） |
| 不支援萬用字元範圍（`*.example.com`） | 階段 1 — 範圍擴充 |
| 沒有偵察工具轉接器 | 階段 2 |
| 沒有 ZAP / Burp 整合 | 階段 3–4 |
| 沒有身分模型與差異化授權測試 | 階段 5 |
| 沒有 LLM 自主規劃循環 | 階段 7 |
| 沒有代理狀態儀表板 | 階段 8 |
| 沒有漏洞懸賞報告草稿產生器 | 階段 9 |

---

## 4. 目標物件模型

### 4.1 證據階梯

本系統的核心紀律。每個箭頭都是獨立且可稽核的晉升，且只有最後一步可由 Verifier 執行。

```
Observation        原始記錄到的現象（回應、標頭、DNS 答案）
    |                  決定性正規化
    v
Candidate          掃描器/啟發式規則認為可能有問題
    |                  Planner 判斷值得調查
    v
Lead               具備信心值與下一步行動的可測試假說
    |                  Verifier 獨立重現並排除良性成因
    v
Finding            可重現、有證據支撐、範圍已確認
```

`nuclei`、ZAP 與 Burp 的結果一律從 **Candidate** 進入。沒有任何程式路徑能讓掃描器結果
直接成為 `Finding`。此規則由 `agent/leads.py:promote_to_finding()` 強制執行，
該函式要求提供帶有證據識別碼的 `VerificationOutcome`。

### 4.2 任務物件

```
Project
  └── Engagement                  （既有：範圍、風險上限、時間邊界）
        └── Mission               自主研究行動的設定與狀態
              └── MissionRun      一段連續執行區間（可從當機恢復）
                    └── AgentCycle    一次 觀察→規劃→行動→驗證 迭代
                          └── AgentTask   循環內的工作單元
                                └── Action  （既有）受政策管制的操作
```

`Action` 保持不變——自主層產生的 `Action` 列與 REST API 產生的完全相同，
並流經同一條政策與執行路徑。

### 4.3 Lead

```
id, engagement_id, mission_id, asset_id
title, hypothesis, category
confidence (0..1), priority (0..100)
status: new|queued|investigating|waiting|needs_approval|verified|rejected|stale|closed
origin: tuple[str, ...]              來源出處，例如 ("openapi-analysis",)
evidence_ids, related_findings
attempt_count, failure_count
last_attempt_at, next_attempt_at
last_reasoning_summary, next_action, blocked_reason
created_at, updated_at
```

**Lead 不等於 Finding。** Lead 承載假說與計畫；Finding 承載證明。

### 4.4 知識庫

每個目標的持續性研究記憶，在**每一次**規劃決策前都會被查詢：

- `Asset` — 主機名稱 / IP / 服務，含首次與最後發現時間
- `Endpoint` — 方法 + 路徑 + 參數，含驗證需求
- `Observation` — 連結到證據的不可變現象紀錄
- `AttackSurfaceSnapshot` — 某時間點攻擊面的內容摘要
- `ChangeEvent` — 兩個快照之間的型別化差異

Planner 在提出行動前必須回答以下問題，而答案來自決定性 SQL，而非 LLM 的記憶：

1. 我們對這個資產/端點已經試過什麼？
2. 哪些假說已經失敗，原因為何？
3. 自上次嘗試以來是否出現新證據？
4. 攻擊面是否改變？
5. 重試是否有正當理由？

---

## 5. 控制流程

### 5.1 任務循環

```python
while mission.active and not kill_switch_engaged:
    cycle = begin_cycle(mission_run)

    observe_environment(cycle)          # 更新盤點、建立攻擊面快照
    detect_changes(cycle)               # 產生 ChangeEvent、喚醒停滯 Lead
    generate_or_update_leads(cycle)     # candidate -> lead
    leads = rank_eligible_leads(cycle)  # 決定性優先度 + 冷卻過濾

    for lead in leads:
        if not budget.permits(lead):
            break
        plan = planner.plan(lead)                 # 結構化 JSON，無副作用
        decision = policy.evaluate(plan)          # decide_action()
        if decision.kind is ALLOW:
            result = operator.execute(plan)       # 既有 worker 路徑
            verifier.evaluate(result)             # 獨立判斷；可能建立 Finding
        elif decision.kind is APPROVAL_REQUIRED:
            lead.block("needs_approval")
        else:
            lead.reject(decision.reason)
        memory.record(cycle, lead, result)

    schedule_next_cycle(mission_run)
```

Worker 永遠不決定下一步。Planner 提案；Policy Engine 決策；Operator 只執行被允許的項目；
Verifier 獨立判斷。

### 5.2 當機與重開機恢復

`MissionRun` 保存 `state`、`heartbeat_at` 與 `cycle_index`。啟動時：

1. 任何處於 `RUNNING` 但心跳超過看門狗門檻的 `MissionRun` 會被標記為 `INTERRUPTED`。
2. `execution/janitor.py:recover_runtime_after_restart()` 清理孤立 worker（已實作）。
3. 停留在 `INVESTIGATING` 的 Lead 會回到 `QUEUED`，且**計入**一次嘗試——
   被中斷的嘗試仍是已使用的嘗試，因此當機迴圈無法對目標造成無限制重試。
4. 新的 `MissionRun` 從持久化的 cycle index 繼續。

沒有任何記憶體內狀態具有權威性。恢復所需的一切都在 PostgreSQL 中。

### 5.3 預算與速率限制

在任何行動被提出之前即強制執行的決定性帳本：

- 每網域每分鐘請求數
- 每任務每小時與每日請求數
- 任務總請求預算
- 每委託/每日/每 Lead 的 LLM token 預算

超出限制會暫停相關工作並發出稽核事件；絕不會靜默丟棄 Lead。
遇到 HTTP 429 或觀察到 WAF 阻擋時，控制器會退避並降低有效速率——
**不會**嘗試規避該控制。

---

## 6. 風險政策對應

與 `policy/risk.py` 一致，此處重述是因為自主執行依賴它：

| 等級 | 意義 | 預設 |
|---|---|---|
| L0 | 被動情報 | 自動 |
| L1 | 低衝擊的授權列舉 | 自動（依委託 `auto_execute_l1`） |
| L2 | 改變狀態 / 類漏洞利用驗證 | 人工核准 |
| L3 | 後滲透 | 人工核准 |
| L4 | 破壞 / 持久化 | **永遠拒絕** |

委託可以**提高**核准要求，但永遠不能降低 L4。任何特定 L2 行為的降級都需要明確的
操作者設定，絕不由代理自行推斷。

自主任務的有效上限為 **L1**。得出 L2 結論時會產生 `needs_approval` 的 Lead
與供人工審閱的計畫草稿——而非執行。

---

## 7. 階段計畫

每個階段都交付程式碼、遷移、測試與雙語文件。

| 階段 | 範圍 | 狀態 |
|---|---|---|
| 1 | Mission Controller、Lead 模型、知識庫、排程器、預算、萬用字元範圍 | **已實作** |
| 2 | 偵察 worker 轉接器（subfinder、dnsx、httpx、naabu、katana、gau、nuclei） | 規劃中 |
| 3 | OWASP ZAP 整合（被動、spider、AJAX spider、API 匯入） | 規劃中 |
| 4 | Burp Suite 轉接器（REST / DAST GraphQL） | 規劃中 |
| 5 | 身分模型與差異化授權測試 | 規劃中 |
| 6 | 完整變更偵測與攻擊面差異驅動的再調查 | 規劃中 |
| 7 | 具結構化輸出與 token 預算的 LLM Planner/Verifier 循環 | 規劃中 |
| 8 | 代理可觀測性儀表板 | 規劃中 |
| 9 | 漏洞懸賞報告草稿產生 | 規劃中 |

### 階段 2 以後的整合規則

每個新掃描器轉接器都遵循既有的四點註冊流程，且一律落在 Candidate，永不落在 Finding：

1. `tooling/registry.py` — 一筆 `_manifest(...)`，其 `name` 必須等於契約的 `kind`
2. `tooling/contracts.py` — 型別化的 `ToolParameters` 子類別，並加入 `ToolParameterUnion`
3. `policy/risk.py` — 在 `ACTION_RISK_LEVELS` 加入 `action_type` 對風險等級的綁定
4. `tooling/executor.py` — 一個 argv 建構分支

掃描器輸出由轉接器專屬的正規化器轉為 `Candidate` 紀錄。
`zap_active_scan` 與任何 Burp 主動掃描皆為 L2，因此需要核准。

---

## 8. 測試策略

- **決定性單元。** 範圍、風險、預算、排程、Lead 合格性與排序皆為無 I/O 的純函式，
  並以包含對抗性輸入的方式詳盡測試。
- **政策繞過測試。** 明確的負向測試，斷言控制器產生、但風險等級被竄改、範圍被放寬
  或核准被偽造的行動一律被拒絕。
- **當機恢復測試。** 任務在循環中途被中斷並恢復；Lead 不得遺失其嘗試計數。
- **僅限本機的整合目標。** 自主端對端測試只對本機刻意設計的易受攻擊應用程式執行。
  CI 絕不掃描公開網際網路；由範圍引擎的預設拒絕加上明確的 localhost 範圍強制保證。

---

## 9. 刻意的限制

- 代理不會向任何漏洞懸賞平台提交報告，只產生供人工審閱的草稿。
- 除非委託明確提供測試身分，否則代理不會建立帳號。
- 代理不會嘗試繞過 CAPTCHA、WAF 或速率限制。
- 分析過程中發現的機密會被遮蔽，且絕不對第三方服務重放。
- 自主執行上限為 L1。其上的一切都是人為決策。
