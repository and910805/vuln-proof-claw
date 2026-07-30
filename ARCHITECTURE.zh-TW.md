# 架構

**繁體中文** | [English](ARCHITECTURE.md)

## 方向

vuln-proof-claw 使用 Python 模組化單體作為控制面，並使用拋棄式 Docker container 執行接觸目標的動作。

```text
CLI / REST API / 未來 Web UI
              │
              ▼
       Python 控制面
  Domain · Policy · Evidence
  Orchestration · Reporting
              │
       ┌──────┴──────┐
       ▼             ▼
  PostgreSQL    Worker Manager
                       │
                       ▼
                拋棄式 Worker
                       │
                       ▼
              已授權 Web/API
```

## Invariant

- Domain code 不依賴 FastAPI、SQLAlchemy、Docker 或 LLM SDK。
- 目標端 Action 執行前必須取得 Scope decision。
- 高風險 Action 必須取得綁定 Action 的 Approval。
- Worker 不取得 Provider credential，也不掛載 Host home directory。
- Raw Evidence 與經 Redaction 的 Report 分開儲存。
- 只有 Verifier 能將 Finding 提升為 `verified`。
- 英文與繁體中文文件保持配對。

## Phase 0

Phase 0 建立 Packaging、Configuration、Identifier、Domain state、Persistence、Policy/Evidence 原語、Health endpoint、CLI diagnostic、Docker Compose、Worker protocol 與 CI，並刻意不提供任何目標端安全工具。

完整核准設計與實作計畫位於 `docs/superpowers/`。
