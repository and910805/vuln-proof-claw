# 受限 Docker Engine backend

**繁體中文** | [English](DOCKER_ENGINE_BACKEND.md)

0.0.18 版新增 authenticated Engine gateway 後方的 privileged adapter。它只透過設定的
local Unix socket 使用 Docker Engine API v1.44，不呼叫 Docker CLI、不讀取
`DOCKER_HOST`、不 follow redirect、不探測 proxy，也不接受任意 daemon URL。

## 獨立 policy gate

除非以下設定全部明確提供，backend 會保持 disabled：

- absolute POSIX Unix-socket path；
- 一個由 `sha256` digest 鎖定的精確 registry image reference；
- 一個專用 Worker network name。

Readiness 要求相容的 Linux Engine、啟用 seccomp、允許的 image 已存在，而且指定 Docker
network 必須是 `Internal=true`。每次 create 前都會再次檢查 runtime assets。

## 固定 create request

Adapter 自行建立 Docker JSON body，gateway caller 不能新增或覆寫欄位。Container 固定使用
允許的 image 與 internal network、非 root user、read-only root、`CapDrop=ALL`、沒有新增
capability、沒有 bind mount、沒有 published port、`no-new-privileges`、PID／CPU／memory
ceiling、有界 tmpfs、停用 auto-remove，以及有界單檔 log configuration。

Caller 無法控制 command、entrypoint、environment、host mount、device、privileged、
namespace 或 socket 欄位。嚴格 Worker request 只透過 Docker 的 stdin-only attach channel
在 start 前送入，不會放進 label、environment variable、command argument 或 Engine log。

## Ownership 與 response handling

Create 之後的每個操作只接受 64 字元小寫 container ID，並重新 inspect container。不可變
owner label、精確 image、internal network、read-only root、dropped capability、
non-privileged mode 與 `no-new-privileges` 必須持續相符。Inventory 只接受已知 ownership
label，且每個結果都會重新 inspect。

Docker JSON body、宣告長度、streamed bytes、attach header、multiplexed log frame 與 decoded
Worker output 都會在解析或配置記憶體前受限。Docker message 與 socket path 只會轉成穩定
backend error code。若 stdin attachment 失敗，剛建立的 container 會連同 anonymous volume
強制移除。

Create conflict 只有在同名 container 具備完全相同 label 且仍通過 ownership inspection 時
才視為 idempotent。Remove 只有在 ID 已不存在時才視為 idempotent；adapter 不會移除 foreign
或安全設定已弱化的 container。

## 部署狀態

Adapter 與 mocked Engine contract 已完成。本版因本機 daemon unavailable，未執行 live Docker
integration test。Compose 不會掛載 Docker socket，runtime startup 仍停用。Published image
digest、scope egress enforcement、process isolation 與 isolated live fixture 完成前，不應啟用
面向目標的執行。
