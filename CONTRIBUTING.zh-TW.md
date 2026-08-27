# 貢獻指南

**繁體中文** | [English](CONTRIBUTING.md)

感謝你協助改善 vuln-proof-claw。

## 開始之前

1. 先搜尋既有 Issue 與 Discussion。
2. 大型架構、安全政策、Schema 或 Dependency 變更前先建立 Issue。
3. 讓變更保持聚焦且可獨立測試。
4. 絕不提交 Secret、客戶資料、未授權測試結果或未取得授權的內容。

## 開發檢查

只使用 Endpoint Security Policy 允許的命令。本倉庫支援 module execution：

```bash
python -m ruff check .
python -m mypy src
python -m pytest
```

經授權的測試可能正常觸發 EDR 或其他防禦告警，應事先與系統擁有者協調告警預期；
不得繞過、停用、竄改 EDR、AppLocker、Sandbox 或組織安全控制，也不得以規避這些控制為設計目標。

## Pull Request

- 說明問題、設計選擇、安全影響與驗證方式。
- 行為變更必須加入測試。
- 英文與 `.zh-TW.md` 文件必須同步更新。
- Public API 應保持向後相容，否則必須提供 migration 文件。
- Commit 使用 DCO sign-off：`git commit -s`。

## Commit 格式

使用簡潔的 conventional prefix，例如 `build:`、`docs:`、`feat:`、`fix:`、`refactor:`、`test:` 與 `ci:`。

## 安全敏感變更

Scope enforcement、Approval、Worker isolation、Command execution、Credential handling 或 Evidence integrity 的變更，必須提供聚焦測試並由 Maintainer 審查。
