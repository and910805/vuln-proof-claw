# 可驗證 Disclosure Bundle

**繁體中文** | [English](DISCLOSURE_BUNDLES.md)

0.6.0 版會將 Engagement 的 JSON、Markdown、安全轉義 HTML 與 SARIF 報告封裝成
單一 Metadata-only ZIP；驗證時不需要伺服器或網路連線。

## 下載與驗證

可在評估結果或歷史紀錄按下「下載可驗證報告包」，或呼叫：

```text
GET /api/v1/engagements/{engagement_id}/report.bundle.zip
```

在本機驗證下載檔案：

```bash
vuln-proof-claw verify-bundle engagement-disclosure.zip
vuln-proof-claw verify-bundle engagement-disclosure.zip --json
```

若 ZIP 結構、Manifest Schema、檔案大小、SHA-256 Digest、安全路徑或 Evidence Chain
連結不正確，驗證指令會以非零狀態結束。

## 內容與資料邊界

- `manifest.json`：Generator、Engagement、Evidence 完整性、逐檔雜湊及僅含 Metadata
  的 Evidence Chain Index。
- `report.json`、`report.md`、`report.html`、`report.sarif`：同一結果的不同格式。
- `README.txt`：離線驗證方式與資料邊界。

壓縮檔排除原始 HTTP Body、Cookie、Browser Storage、登入憑證、Provider Secret 與
環境設定。Manifest 固定宣告 `raw_evidence_included: false`，更動此政策會被拒絕。

驗證器不會解壓縮檔案，並會拒絕絕對或上一層路徑、反斜線、目錄、重複檔名、
加密 Entry、過多檔案、過大資料、可疑壓縮比及未在 Manifest 宣告的檔案。

SHA-256 完整性只能證明檔案仍與 Manifest 相符，不能證明建立者身分；密碼學簽章
屬於後續獨立功能。
