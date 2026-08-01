# Web 控制台

**繁體中文** | [English](WEB_UI.md)

內建 Web 控制台是 ProofClaw 第一個可互動的控制介面。它是一個 React 與 TypeScript 單頁應用程式，由 FastAPI 程序直接提供，因此預設 Docker Compose 部署只會暴露一個本機端點，不需要另外架設 Web Server。

## 目前範圍

Web 基礎版本目前提供：

- 英文與繁體中文介面。
- 即時 API 與資料庫 readiness 狀態。
- 持久化控制平面數量摘要。
- 專案清單與建立專案。
- 系統強制執行的 L0-L4 風險政策參考。
- 如實標示已運作與仍鎖定的能力。

目前還不能透過 Browser 啟動 Flow、執行面向目標的工具、批准 Action、顯示原始 Evidence 或驗證 Finding。Workflow 與具 Authentication 的 Approval API 已存在，但 Web credential session 與上述控制項仍刻意維持不可用。

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
- 建立專案目前只供本機 pre-alpha 使用；正式環境部署前必須完成 Authentication readiness。
- UI 是否顯示按鈕不是授權邊界；Policy、Scope、Approval 與 Execution 檢查仍由 Server 強制執行。
- 未完成的 Action 不會以模擬方式執行，也無法從瀏覽器開啟。

## API contract

基礎 UI 使用：

- `GET /api/v1/health/ready`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/projects`
- `POST /api/v1/projects`
