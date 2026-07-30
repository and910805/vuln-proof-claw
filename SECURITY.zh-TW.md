# 安全政策

**繁體中文** | [English](SECURITY.md)

## 支援版本

vuln-proof-claw 目前是 pre-alpha 軟體。在第一個版本化發行前，安全修正會套用至 `mainer` 的最新 commit。

## 通報漏洞

若漏洞可能導致 credential 洩漏、Worker 逃逸、Scope 或 Approval Policy 繞過、非預期命令執行、Evidence 竄改或影響其他使用者，請勿建立公開 Issue。

請使用本倉庫的 GitHub Private Vulnerability Reporting，並提供：

- 簡潔說明與受影響 revision。
- 重現步驟或最小測試案例。
- 預期與實際行為。
- 安全影響與必要前提。
- 可選的修補建議。

請勿包含真實客戶資料、有效 credential，或從未獲授權系統取得的結果。

## 回應目標

- 初次確認：5 個工作天內。
- Triage 決定：10 個工作天內。
- 修補時程：確認嚴重度與可利用性後通知。

以上是處理目標，不構成服務等級保證。

## 安全研究

研究只能使用自己擁有或已取得明確授權的系統。請避免侵犯隱私、建立持久化、破壞性操作與不必要的資料存取。若繼續測試可能傷害使用者或基礎設施，必須立即停止。
