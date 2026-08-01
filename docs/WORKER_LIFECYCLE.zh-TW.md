# 拋棄式 Worker 生命週期預覽

**繁體中文** | [English](WORKER_LIFECYCLE.md)

0.0.8 版加入內部、與 runtime 實作無關的生命週期協調器。這不是公開掃描
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

## 目前限制

生命週期 registry 目前只存在單一 process 內，而且只接受注入的 runtime 實作。
在啟用面向目標的執行前，仍須完成重啟復原、持久化 Worker registry、受限 Docker
adapter、DNS pinning、scope egress、串流輸出限制與隔離式端對端目標測試。預設的
`DisabledWorkerManager` 仍維持 fail closed。
