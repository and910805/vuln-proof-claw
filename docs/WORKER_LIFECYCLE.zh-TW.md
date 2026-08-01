# 拋棄式 Worker 生命週期預覽

**繁體中文** | [English](WORKER_LIFECYCLE.md)

0.0.15 版提供內部生命週期協調器與受限 container policy adapter。這不是公開掃描
endpoint，也不會啟用 Docker 或網路執行 adapter。

## 強制執行順序

1. 載入 queued Action，並把所有受保護的 Worker 欄位與持久化 Action、Scope
   狀態逐一比對。
2. 重新執行 policy 與 approval 檢查。
3. 建立尚未啟動的拋棄式 Worker。
4. 以單一交易把 Action 轉為 `running`，並消耗綁定的 Approval。
5. 啟動 Worker、收集一個終止回應，且無論結果都嘗試清理。
6. 保存 `succeeded`、`failed`、`timed_out`、`cancelled` 或 `worker_lost`，並追加
   create／start／collect／cancel／destroy 稽核事件。

成功回應至少要引用一筆已保存的 Evidence，而且每筆 Evidence 都必須屬於同一
Action。Evidence 不存在或跨 Action 時，持久化的 Action 結果會改為 `failed`。

## 持久化 registry 與重啟行為

lifecycle metadata 會保存於 `worker_executions`，具 optimistic version，以及唯一
Action、request 綁定。registry 會保存 Worker ID、runtime identity、狀態、時間、
cleanup 結果與安全 error code；刻意不保存 privileged runtime reference。

adapter 可在啟動時執行整合式 recovery。它會先把 abandoned `starting`、`running`
紀錄轉成 `lost`，並把對應 queued 或 running Action 轉為 `worker_lost`；接著盤點
應用程式擁有的 runtime resource、保留仍存活的綁定，並刪除終止或 orphan 資源。
兩個階段都會追加安全的 Engagement 稽核事件。詳見
[Runtime 資源清理器](RUNTIME_JANITOR.zh-TW.md)。

## 目前限制

process-local lifecycle 現在可接受完整受限 container policy adapter，包含 digest
pinning、固定 privilege control、資源上限、有界 protocol I/O、inventory 與 cleanup。
在啟用面向目標的執行前，仍須完成 privileged authenticated Engine transport、scope
egress、Worker executor、啟動 wiring 與隔離式端對端目標測試。預設的
`DisabledWorkerManager` 仍維持 fail closed。
