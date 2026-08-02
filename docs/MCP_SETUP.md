# Codex and Claude Code MCP Setup

[繁體中文](MCP_SETUP.zh-TW.md) | **English**

The local `vuln-proof-claw-mcp` stdio server exposes six tools: health, run assessment,
create automation plan, get assessment, get report, and list findings. It calls the local
ProofClaw REST API. It does not store model-provider credentials and does not bypass API
authentication, scope, policy, or Approval.

Install the project and start the API first. Keep the control-plane token in your user
environment, not in a committed file:

```powershell
$env:PROOFCLAW_API_URL = "http://127.0.0.1:8080"
$env:PROOFCLAW_API_TOKEN = "<operator-token>"
```

## Codex

Add this to trusted project `.codex/config.toml` or your user Codex config. Use an absolute
Python path for reliable stdio startup:

```toml
[mcp_servers.proofclaw]
command = "C:/absolute/path/vuln-proof-claw/.venv/Scripts/python.exe"
args = ["-m", "vuln_proof_claw.mcp_server"]
env_vars = ["PROOFCLAW_API_URL", "PROOFCLAW_API_TOKEN"]
default_tools_approval_mode = "prompt"
```

## Claude Code

Create a project-scoped `.mcp.json` only if your team trusts the command. The token is
expanded from the user environment:

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

Claude Code asks before trusting a project-scoped server. Check it with `/mcp`. Do not
commit a literal token. The MCP server writes protocol messages only to stdout; operational
errors are returned as MCP tool errors without echoing the API token.
