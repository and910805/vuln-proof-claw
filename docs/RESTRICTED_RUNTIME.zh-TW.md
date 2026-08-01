# 受限 Docker runtime 邊界

**繁體中文** | [English](RESTRICTED_RUNTIME.md)

0.0.15 版實作在連接任何 privileged Docker transport 前使用、與 runtime transport
無關的安全政策與完整 `WorkerRuntime` lifecycle。此功能仍預設停用，也不會讓任意
安全工具直接執行。

## 信任邊界

`DockerWorkerRuntime` 不會取得 Docker socket 或一般用途 Docker client，而是依賴窄化的
`RestrictedDockerEngine` 介面；未來必須由經過驗證的 socket proxy 或隔離 execution
service 實作。該介面只接受完整 `RestrictedContainerSpec`，刻意不提供 command、
entrypoint、environment、host mount、device、privileged mode、host network 或新增
capability 等逃生欄位。

每個產生的 spec 都會強制：

- image 必須由小寫 SHA-256 digest 固定；
- 使用專用 network，且不得為 `host`、`bridge`、`none` 或 `control-plane`；
- 使用非 root UID／GID `10002:10002`；
- 唯讀 root filesystem、`no-new-privileges`、init 與 `cap_drop=ALL`；
- 限制 CPU、記憶體、PID、timeout、request、response 與 tmpfs 大小；
- task 與 temporary tmpfs 使用 `noexec,nosuid,nodev`；
- 固定使用 image entrypoint，嚴格 Worker request 只透過有大小限制的 stdin 傳入；
- 使用不可變 Worker ID、request ID、建立時間、owner 與 runtime identity label。

## Request 與 response 強制規則

在接觸 Engine 前，adapter 就會拒絕 allowlist 外 capability，以及超過政策上限的任何
request limit。Worker ID 必須是 canonical UUID，request ID 不得包含控制字元，而且
序列化 request 必須符合 byte 上限。

Engine 收集 stdout 時必須限制大小。Adapter 接著驗證嚴格 `v1` `WorkerResponse`、比對
回報 exit code 與 Engine exit code，最後只回傳 protocol object。無效或過大的輸出會
轉為穩定 error code；raw output 與 privileged reference 不會出現在物件表示或公開
exception。

## Identity 與 inventory

Runtime identity 同時包含 digest-pinned image，以及所有安全相關 policy 欄位的 SHA-256
摘要。因此修改資源上限、network、user、tmpfs 或 capability allowlist 都會產生不同
identity。Inventory 先依 owner 與完全相符的 runtime identity 過濾，再驗證所有不可變
label，才會回傳 janitor resource。

## 設定閘門

`VULN_PROOF_CLAW_DOCKER__RUNTIME_ENABLED` 預設為 `false`。建立 policy 必須明確啟用，
且 image 必須固定 digest；production 設定還必須具備 API authentication readiness。
這些檢查不能取代 Authorization、Scope、Approval 或 Worker 本地 network policy。

## 刻意保留的待辦

本版不提供 Docker socket mount、Docker CLI subprocess、TCP Docker API client 或啟動
wiring。啟用 runtime 前，仍必須實作並安全審查專用 authenticated Engine gateway、
scope egress enforcement、digest 發布流程、Worker-side executor 與隔離式端對端目標測試。
