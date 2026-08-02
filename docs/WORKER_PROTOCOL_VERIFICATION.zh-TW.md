# Worker 協定驗證

**繁體中文** | [English](WORKER_PROTOCOL_VERIFICATION.md)

0.0.19 版讓受限制的 Worker 映像從標準輸入讀取一筆有大小上限的 v1
`WorkerRequest`。有效請求會得到嚴格且綁定原請求的 `WorkerResponse`，狀態為
`policy_denied`，錯誤碼為 `worker_execution_not_implemented`。Worker 不會對目標
發出網路請求，也不會建立證據或產物 ID。無效或超限輸入只會收到固定錯誤格式，
輸入內容不會被反射到輸出。

這是協定與容器生命週期的里程碑，不是目標執行器。它能在不把 mock 證據冒充成功
的前提下，驗證請求附加、輸出上限、結束碼核對與控制面關聯。

## CI 映像身分

容器工作流程會用 OCI revision label 將映像綁定到原始碼 commit，並在每份 SBOM
旁上傳嚴格的 JSON 身分紀錄。紀錄包含本機 image ID、原始碼 revision、平台、
Dockerfile 雜湊，以及 Docker 回報的 repository digest。本機 image ID 不是登錄庫
發布 digest，不可作為執行期 allowlist。

## 選擇性實機驗證

實機測試預設停用。在具備內部 Worker 網路，且已準備好以 registry digest 固定映像
的 Linux 主機上，設定：

```text
VULN_PROOF_CLAW_RUN_WORKER_INTEGRATION=1
VULN_PROOF_CLAW_TEST_WORKER_IMAGE=registry.example/worker@sha256:<64 hex>
VULN_PROOF_CLAW_TEST_WORKER_NETWORK=vuln-proof-claw-workers
```

接著執行 `pytest tests/integration/test_live_worker_runtime.py`。測試會使用正式 Docker
Engine adapter 建立並清除一個受強化的 Worker，且預期收到綁定原請求的安全拒絕；
它不會連線到目標網址。
