# Web 控制台

**繁體中文** | [English](WEB_UI.md)

內建 Web 控制台是 ProofClaw 第一個可互動的控制介面。它是一個 React 與 TypeScript 單頁應用程式，由 FastAPI 程序直接提供，因此預設 Docker Compose 部署只會暴露一個本機端點，不需要另外架設 Web Server。

## 目前範圍

Web 基礎版本目前提供：

- 英文與繁體中文介面。
- 即時 API 與資料庫 readiness 狀態。
- 持久化控制平面數量摘要。
- 專案清單與建立專案。
- 可用 deep link 直接開啟的授權 URL 評估工作區。
- 根據已確認目標，自動建立範圍縮到最小的 24 小時 L0 Engagement。
- 被動評估狀態、Evidence／Finding 數量，以及 JSON／Markdown 報告下載。
- 供 authentication deployment 選用的 Operator Bearer Token 輸入。
- 系統強制執行的 L0-L4 風險政策參考。
- 如實標示已運作與仍鎖定的能力。

Browser 目前只能啟動有界的被動 URL assessment，不會 crawl、登入目標、執行外部工具或 payload、批准高風險 Action、顯示原始 Evidence，或獨立驗證 Finding。

## 開啟控制台

啟動服務：

```bash
docker compose up --build -d
```

開啟 <http://127.0.0.1:8080/>。API 文件仍位於 <http://127.0.0.1:8080/docs>。

## 前端開發

需求：Node.js 22 以上與 npm。

```bash
cd web
npm ci
npm test
npm run typecheck
npm run build
```

正式建置會輸出至 `src/vuln_proof_claw/web`，並與 Python 應用程式一起封裝。如需使用 Vite hot reload，請先在 8080 埠啟動 FastAPI，再執行：

```bash
cd web
npm run dev
```

Vite 只監聽 `127.0.0.1:5173`，並將 `/api` 代理至 `127.0.0.1:8080`。

## 安全姿態

- UI 使用 same-origin API request，不載入外部 CDN 資源。
- Compose API 預設仍只綁定 `127.0.0.1`。
- 選用的 Operator Token 只保存在分頁範圍 `sessionStorage`，不會放進 URL，並可明確清除。正式多使用者環境仍須先完成更完整的 hardened session strategy。
- 送出前會移除 query string 與 fragment，拒絕內嵌 credential、IP literal 與非 HTTP(S) scheme，並要求使用者明確確認授權。Private 與 IP-literal target 必須另外透過人工審查後的 API Scope 建立。
- 自動建立的 Engagement 只允許目標 hostname、scheme、port 與 path；24 小時後失效、maximum risk 固定為 L0，且 destructive action 維持停用。
- UI 是否顯示按鈕不是授權邊界；Policy、Scope、Approval 與 Execution 檢查仍由 Server 強制執行。
- Server 未啟用 assessment setting 前，UI 不會送出 target traffic。

## API contract

基礎 UI 使用：

- `GET /api/v1/health/ready`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/projects`
- `POST /api/v1/projects`
- `POST /api/v1/projects/{project_id}/engagements`
- `POST /api/v1/engagements/{engagement_id}/assessments`
- `GET /api/v1/engagements/{engagement_id}/report`
- `GET /api/v1/engagements/{engagement_id}/report.md`
