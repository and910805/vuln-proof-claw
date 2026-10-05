# 工具執行與 Agent 自主性

**繁體中文** | [English](TOOL_RUNTIME.md)

0.7.0 版讓 REST、MCP、Policy 與後續 Worker Adapter 共用同一份 Tool Registry。
登錄工具不等於宣稱已可執行：

| 狀態 | 意義 |
| --- | --- |
| `cataloged` | 已定義能力、執行檔、風險與預定 Adapter；執行請求會被拒絕。 |
| `contract_ready` | 已有嚴格 Request Contract，但尚無預設 Worker Runner。 |
| `worker_ready` | 已有可供一次性受限 Worker 使用的有界 argv Builder。 |

首批目錄包含 Shell、Python、Nmap、密碼測試、Exploit／PoC、httpx、Nuclei、Nikto、
ffuf、Feroxbuster、Gobuster、Katana、sqlmap、Dalfox、testssl.sh、OWASP ZAP、Wapiti、
WhatWeb、WAFW00F、Subfinder、Amass、Semgrep 與 Trivy。新工具必須先宣告 Action Type
與 Risk 才能進入規劃。

## 執行契約

- `shell_command` 只接受執行檔 basename 與 argv array，不接受 Shell Command Line；
  Worker 必須 Allowlist 執行檔並使用 `shell=False`。
- `python_execute` 將有界 Source 與參數交給隔離、限制網路的 Worker，使用 Python
  isolated flags，風險為 L2。
- `nmap` 只從 Ports、Service Detection 與 Registry Script Name 建立 TCP connect scan，
  不接受 Raw Flag。
- `password_test` 接受 Username 與 Secret Store Reference，不接收 Raw Password；最多
  100 次、每分鐘最多 30 次，預設成功即停止。
- `exploit_poc` 必須提供 Registry ID、Artifact SHA-256、成功訊號，且最多十次；Request
  不內嵌 Exploit Payload。
- `httpx` 只探測一個已核准的標的，探測項是有界枚舉。它不提供標的檔案、埠清單、額外路徑、
  Proxy，也不跟隨轉址——每一項都是「標的可以從別的地方來」的第二個入口。
- `nuclei` 用 Template ID、Tag 與 Severity 從 Worker Image 內釘住的 Corpus 挑選 Template，
  永不接受 Template 路徑：路徑是核准之後才選定、核准當時沒看過內容的第二份 Corpus。
  頻外偵測（OAST）預設關閉，除非明確指定 interactsh Server，所以不可能誤用原廠的公開
  OAST 伺服器。argv 同時關掉每一個會超出標的或送出主機外的 nuclei 預設行為：更新檢查、
  從 stdin 讀標的、雙 Scheme 探測、公開 DNS Resolver，以及 Template 自行跟隨轉址。

nuclei 有兩個輸入不在 argv 裡：`$HOME/.config/nuclei/config.yaml` 可以設定任何選項，包含
`-proxy` 與 `-list`；以及環境變數，Cloud Upload 不需要任何旗標就能從環境變數啟用。因此
Parameter Digest 本身並不足以釘住 nuclei 的行為。`tooling/executor.py` 裡的
`NUCLEI_WORKER_ENVIRONMENT` 明列 Worker 必須設定與必須清除的變數；忽略它的 Worker
仍然可能被一個設定檔改變行為。

每個計畫都會正規化、計算 Digest、建立 Flow／Task／Action、檢查 Engagement Scope 與
Maximum Risk，再寫入 Audit Log。L2 必須取得精確 Approval 或套用 Approval Preset。
只有建立 Engagement 時明確設定 `auto_execute_l1: true`，L1 才會自動執行。

## Agent 自主循環

自主控制器會選擇 `plan`、`operate`、`wait_for_approval`、`verify`、`complete` 或 `stop`。
批准優先於操作、驗證優先於完成；Step、Tool Call、Duration 或連續失敗達上限時停止。
Planner、Operator、Verifier 決策可透過 REST 與本機 Codex／Claude Code MCP 使用。

經授權測試可能正常觸發 EDR 或其他告警，這是需要協調的營運事件，不應因此移除有效
測試能力。ProofClaw 不提供告警規避、防禦控制竄改或停用 EDR。
