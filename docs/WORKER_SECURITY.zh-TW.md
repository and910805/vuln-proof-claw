# Worker 與容器安全

**繁體中文** | [English](WORKER_SECURITY.md)

本文件定義 Phase 0 的容器信任邊界。這些內容是安全要求，不代表只靠容器隔離就足以安全執行敵意工作負載。

## 目前邊界

- API 與 Worker image 都使用各自的非 root 使用者執行。
- Compose API service 使用唯讀 root filesystem、移除全部 Linux capability、啟用 `no-new-privileges`，並限制 CPU、記憶體、PID 與暫存空間。
- PostgreSQL 只能從 Compose control-plane network 存取，不發布到 host。
- 只有 API health endpoint 發布於 `127.0.0.1:8080`。
- Worker image 不掛載 Docker socket、host home directory、credential store 或 control-plane provider credential。
- Compose 預留不具外部 egress 的 internal-only `vuln-proof-claw-workers` network。
- lifecycle coordinator 會稽核 create／start／collect／cancel／destroy、強制 timeout，並透過注入的 process-local runtime boundary 一律嘗試清理。
- 安全的 lifecycle metadata 會持久化，重啟後 abandoned in-flight 紀錄會 reconcile 成明確的 lost 狀態。
- Runtime inventory 使用不可變的 Worker／request 標籤；終止與 orphan 資源會在有界 grace period 後移除，並留下安全稽核事件。
- 預設 `DisabledWorkerManager` 仍採 fail-closed，不執行任何面向目標的操作。

Compose 預設值只供本機開發使用。預設資料庫密碼不適用於共享或 production 環境。

## Docker socket 威脅

Docker socket 存取權實質上等同 host 管理權限。擁有不受限制 socket 權限的程序可以建立 privileged container、掛載 host 路徑、讀取環境變數，並逃離預期的 Worker 邊界。

因此：

1. 絕對不要把 `/var/run/docker.sock` 掛載進 API 或 Worker container。
2. 絕對不要透過未驗證的 TCP endpoint 公開 Docker API。
3. 未來的 Docker Worker Manager 必須視為獨立的高權限安全邊界。
4. Manager 必須使用窄化 request schema，並對 image、mount、network、resource 與 lifecycle 操作建立 allowlist。
5. 必須拒絕 host 路徑、Docker socket、privileged mode、新增 capability、host networking 與未核准 image。
6. 必須稽核每次 Worker create、start、cancel、collect 與 destroy。
7. 優先使用受限 socket proxy 或獨立 execution service，而非直接存取 socket。

## Worker 不變條件

每個具體 Worker Manager 都必須強制執行：

- 僅接受精確的 `v1` protocol schema，拒絕未知欄位。
- 使用 canonical target 與 Worker 本地的核准 scope 副本。
- L2–L4 request 必須綁定 approval identifier。
- 每個 Action 使用可拋棄的 Worker 與 task directory。
- 在工具允許時使用唯讀 root filesystem。
- 明確限制 CPU、記憶體、PID 與 timeout。
- Network egress 必須受核准 scope 限制，包含 DNS、redirect、browser subresource 與 proxy。
- Worker request 與環境不得包含 control-plane LLM credential。
- 清理 Worker 前必須先收集 Evidence。
- 無論成功、失敗、逾時、取消或 worker lost，都必須完成清理。

## 目前限制

控制平面目前已定義並測試生命週期狀態機、持久化 registry、Action 綁定、Approval
消耗、response 綁定、Evidence 驗證、稽核軌跡、timeout、取消、清理與 fail-closed
重啟 reconciliation，以及與 runtime 無關的 orphan-resource janitor，但尚未提供
具體 runtime、重新接管存活 container、把 recovery 接入啟動流程，或執行安全測試
工具。在完成並驗證 network policy enforcement、受限 runtime adapter、啟動整合與
隔離式端對端目標前，internal-only Worker network 會維持封閉。
