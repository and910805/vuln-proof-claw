# Codex 與 Claude Code MCP 設定

**繁體中文** | [English](MCP_SETUP.md)

本機 `vuln-proof-claw-mcp` stdio Server 提供六個工具：Health、執行 Assessment、建立 Automation
Plan、取得 Assessment、取得 Report 與列出 Findings。它只呼叫本機 ProofClaw REST API，不保存模型
供應商憑證，也不能繞過 API Authentication、Scope、Policy 或 Approval。

請先安裝專案並啟動 API。Control Plane Token 應放在使用者環境，不可寫入 Git：

```powershell
$env:PROOFCLAW_API_URL = "http://127.0.0.1:8080"
$env:PROOFCLAW_API_TOKEN = "<operator-token>"
```

## Codex

在受信任專案的 `.codex/config.toml` 或使用者 Codex Config 加入下列設定。stdio 啟動路徑請使用絕對路徑：

```toml
[mcp_servers.proofclaw]
command = "C:/absolute/path/vuln-proof-claw/.venv/Scripts/python.exe"
args = ["-m", "vuln_proof_claw.mcp_server"]
env_vars = ["PROOFCLAW_API_URL", "PROOFCLAW_API_TOKEN"]
default_tools_approval_mode = "prompt"
```

## Claude Code

只有在團隊信任該 Command 時才建立 project-scoped `.mcp.json`。Token 由使用者環境展開：

```json
{
  "mcpServers": {
    "proofclaw": {
      "type": "stdio",
      "command": "C:/absolute/path/vuln-proof-claw/.venv/Scripts/python.exe",
      "args": ["-m", "vuln_proof_claw.mcp_server"],
      "env": {
        "PROOFCLAW_API_URL": "${PROOFCLAW_API_URL:-http://127.0.0.1:8080}",
        "PROOFCLAW_API_TOKEN": "${PROOFCLAW_API_TOKEN}"
      }
    }
  }
}
```

Claude Code 會要求信任 project-scoped Server，可用 `/mcp` 檢查。不可 commit 明文 Token。MCP Server
只在 stdout 輸出 Protocol Message；執行錯誤會以 MCP Tool Error 回傳，且不會輸出 API Token。
