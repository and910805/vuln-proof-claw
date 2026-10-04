# 執行自主任務

如何定義、註冊並操作長時間執行的自主研究任務。
設計與階段計畫請見 [AUTONOMOUS_AGENT_ARCHITECTURE.zh-TW.md](AUTONOMOUS_AGENT_ARCHITECTURE.zh-TW.md)。

---

## 1. 撰寫委託定義

委託檔案是「程式方授權了什麼」的書面紀錄，也是範圍、程式規則與速率限制的**唯一**來源。
系統不會推斷任何授權邊界，代理也永遠無法擴大它。

請從 [`examples/engagement.yaml`](../examples/engagement.yaml) 開始。

```yaml
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z

scope:
  include:
    - "*.example.com"       # 僅比對嚴格子網域
    - "api.example.com"     # 頂點網域必須明確列出
  exclude:
    - "status.example.com"
    - "*.thirdparty.example"
  allowed_ports: [443]
  allowed_schemes: ["https"]

program:
  program_name: Example Bug Bounty
  prohibited_testing: ["denial of service", "social engineering"]

rate_limits:
  requests_per_minute_per_domain: 5

risk_policy:
  maximum_risk: L1
  auto_execute_l1: true
  maximum_autonomous_risk: L1
```

### 值得注意的範圍規則

- `*.example.com` **只**比對嚴格子網域，不會授予 `example.com`；
  若程式方確實授權頂點網域，請另外列出。
- 拒絕規則在允許規則**之前**評估，且永遠勝出，包括勝過明確允許的主機名稱。
- 基底為公開後綴的萬用字元（`*.co.uk`、`*.com`）會被拒絕。
- 萬用字元絕不套用於 IP 字面值。
- 時間戳必須含時區。在授權時間窗之外，所有目標都會被拒絕
  （`engagement_not_started` / `engagement_expired`）。

## 2. 註冊前先驗證

```bash
vuln-proof-claw mission validate examples/engagement.yaml
```

此指令會將檔案解析為政策引擎實際強制執行的正規化範圍並印出。
請確實閱讀：這才是授權內容，而非你以為自己寫下的內容。

加上 `--json` 可取得穩定的 `v1` 文件。

## 3. 註冊委託與任務

```bash
vuln-proof-claw mission create examples/engagement.yaml
```

這會建立專案、委託、正規化範圍，以及一個處於 `pending` 狀態的任務，
並印出後續指令所需的 `mission_id`。

## 4. 操作任務

```bash
vuln-proof-claw mission status <mission_id>
vuln-proof-claw mission pause  <mission_id>
vuln-proof-claw mission resume <mission_id>
vuln-proof-claw mission stop   <mission_id> --kill-switch
```

`status` 會回報任務狀態、目前執行區間與循環索引、依狀態分類的 Lead 計數，
以及已知攻擊面的規模。

`pause` 停止開始新循環但不丟棄狀態。`--kill-switch` 會額外啟動一個旗標，
無論狀態為何都會阻擋所有後續循環。

---

## 5. 一次循環做了什麼

```
observe      建立攻擊面快照
detect       產生 ChangeEvent；喚醒攻擊面已變動的停滯 Lead
age          將長期未處理的 Lead 標記為 stale
rank         以決定性優先度排序合格 Lead
work         在預算內逐一處理 Lead：
               回想記憶 -> 規劃 -> 驗證 -> 政策 -> 執行 -> 記錄
```

Lead 只有在**全部**符合以下條件時才算**合格**：

- 狀態為 `new`、`queued` 或 `waiting`
- 未被封鎖等待人工決策
- 嘗試次數低於 `maximum_lead_attempts`
- 冷卻時間已過
- **若先前曾失敗，自上次嘗試後必須已有新證據**

最後一條規則正是代理不會定時重跑同一個失敗假說的原因。
「新證據」指已儲存的觀察或變更事件——而非代理自己主張值得重試。

## 6. 你可以依賴的安全特性

| 特性 | 強制執行位置 |
|---|---|
| 沒有 `ALLOW` 政策決策就不會執行任何事 | `policy/decision.py:decide_action`，並由 `execution/authorization.py` 再次執行 |
| 無人值守執行上限為 L1 | `domain/autonomous.py:Mission.__post_init__` |
| Planner 無法自行選擇風險等級 | `agent/planner.py:validate_plan`，之後是 `decide_action` |
| 範圍外目標一律拒絕 | `policy/scope.py:evaluate_scope`，預設拒絕 |
| 被中斷的嘗試仍然計數 | `agent/leads.py:begin_attempt` |
| 只有驗證能建立 Finding | `agent/leads.py:promote_to_finding` |
| 絕不嘗試破壞性證明 | `verification_verdict` → `needs_manual_review` |
| 速率限制在提出行動前即檢查 | `agent/budget.py:BudgetGate.permits_request` |

遇到 HTTP 429 或觀察到 WAF 阻擋時，控制器會退避並降低有效速率。
它**不會**嘗試規避該控制，破解 CAPTCHA 在設計上亦排除在外。

## 7. 當機與重開機恢復

沒有任何記憶體內狀態具有權威性。啟動時控制器會：

1. 將心跳逾期的執行區間標記為 `interrupted`；
2. 將卡在 `investigating` 的 Lead 退回 `queued`，且嘗試次數已計入；
3. 從持久化的循環索引繼續。

```python
controller.recover(watchdog_seconds=900)
run = controller.start_run()
report = controller.run_cycle(run)
```

## 8. 目前的限制

- 自主執行目前驅動被動 HTTP 擷取路徑（`public_page_read`，L0）。
  偵察工具轉接器於階段 2 加入。
- 變更偵測目前記錄「新增」。移除偵測與更豐富的型別化差異屬於階段 6。
- 階段 1 的 Planner 是決定性的，不進行任何模型呼叫。
  LLM Planner、其結構化提示與 token 計量屬於階段 7。
- 目前沒有 HTTP 儀表板；在階段 8 之前，`mission status` 即為操作者視圖。
- 報告由既有的 reporting 模組產生。漏洞懸賞報告草稿產生屬於階段 9。
