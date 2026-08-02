# Runtime 資源清理器

**繁體中文** | [English](RUNTIME_JANITOR.md)

0.0.14 版定義並測試未來受限 runtime adapter 使用的清理契約，避免控制平面重啟後，
拋棄式資源無限期殘留。這項能力本身不會啟用任何面向目標的執行。

## Runtime inventory 契約

每個屬於本應用程式的資源都必須提供不可變、非機密的 metadata：

- 控制平面的 Worker ID；
- protocol request ID；
- 含時區的建立時間；
- 只供 privileged adapter 內部使用的不透明 runtime reference。

Runtime identity 必須指向不可變的實作或 image。Inventory 只能回傳本應用程式擁有的
資源。建立資源前就必須綁定 Worker ID，而且 `destroy` 必須具冪等性。不透明 reference
不得出現在結果表示、持久化資料或稽核 payload。

## 重啟順序

啟動 adapter 會透過 `recover_runtime_after_restart` 依序執行：

1. 將持久化的 `starting`、`running` execution 轉為 `lost`，並將對應 Action 轉為
   `worker_lost`。
2. 盤點設定 runtime 所擁有的資源。
3. 保留仍綁定非終止 registry 紀錄的資源。
4. 刪除已終止、過期、綁定不符或未登記的資源。
5. 保存成功的 cleanup 結果，並追加安全的稽核事件。

未登記或綁定不符的資源預設會等待五分鐘 grace period，以保護 runtime 建立到 registry
寫入之間的短暫區間；已終止紀錄不需等待。每次 sweep 會序列化執行，重複的 runtime
reference 最多只會刪除一次。

## 安全結果

Sweep 結果只包含 Worker ID、request ID、狀態與穩定 reason code。Runtime exception
只會轉換成 `worker_runtime_inventory_failed` 或 `cleanup_failed`。若資源已刪除，但
optimistic registry update 發生競態，結果會是 `registry_update_conflict`，並由專用
稽核事件標示持久化一致性問題，而且不會重新建立已刪除的資源。

稽核事件類型如下：

- `worker.janitor_destroyed`；
- `worker.janitor_cleanup_failed`；
- `worker.janitor_registry_update_failed`。

## 目前邊界

本版完成 inventory、reconciliation、cleanup、audit 與受限 container-policy
adapter 與 authenticated Engine client/server 邊界。Privileged Engine adapter、Worker executor、scope egress 與啟動 wiring 仍
刻意不提供，因此預設仍使用 `DisabledWorkerManager`，任意工具仍無法執行。
