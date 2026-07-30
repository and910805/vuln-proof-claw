# 專案治理

**繁體中文** | [English](GOVERNANCE.md)

## 角色

- **Maintainer** 核准 Release、架構、安全政策與 Contributor access。
- **Reviewer** 提供領域審查，但不能核准自己的變更。
- **Contributor** 依專案政策提交 Issue、文件、測試與程式碼。

## 決策

一般決策透過經審查的 Pull Request 完成。架構、安全邊界、Public API 與治理變更必須具有文件化提案並取得 Maintainer 核准。

安全 invariant 的優先級高於相容性與交付速度。LLM output、Plugin、Playbook 或 User prompt 都不能覆蓋由程式碼強制執行的 deny rule。

## Release

Maintainer 核准版本號與 Release Note。Release 必須列出已知限制、Migration requirement、安全相關變更與驗證狀態。

## 專案資產

Repository access、Package name、Signing key、Domain 與 Release credential 都是專案資產。存取必須遵循最小權限，且不再需要時立即移除。

## 修訂

治理變更必須同步更新英文與繁體中文文件，並透過公開 Pull Request 完成。
