# 威脅模型

**繁體中文** | [English](THREAT_MODEL.md)

## 範圍

Phase 0 涵蓋控制面基礎與 Worker protocol，不執行 Scan、LLM Action、任意 Shell command 或 Browser automation。

## 受保護資產

- Provider 與 Database credential。
- Engagement scope 與 Approval record。
- Raw Evidence、Hash、Report 與 Audit event。
- Host filesystem、Docker daemon、Worker image 與 Project data。

## 信任邊界

- User/CLI 至 API。
- API 至 PostgreSQL。
- Control plane 至 Worker Manager。
- Worker Manager 至拋棄式 Worker。
- 未來 Worker 至已授權 Target。
- 未來 Control plane 至外部或本機 LLM Provider。

## 主要威脅

- 透過 DNS、Redirect、IPv4/IPv6 ambiguity、Proxy 或 Browser subresource 繞過 Scope。
- Approval replay 或 Parameter mutation。
- Operator／Approver token 遭竊、角色混淆，或 Credential 透過 URL 與 Log 洩漏。
- 目標控制資料造成的 Prompt injection。
- Worker escape、不安全 Mount、Docker socket 濫用或 Credential leakage。
- Command/path injection 與惡意 Plugin。
- Evidence 刪除、重新排序、替換或 Report 不實呈現。
- Cross-project data leakage 與 Denial of Service。

## 必要控制

- 在執行時由程式碼強制執行 Scope check。
- L0-L4 Risk Policy 與綁定 Action 的 Approval。
- Operator 與 Approver 職責使用分離且以 constant-time 比對的 Bearer Credential。
- 具 Resource 與 Network limit 的拋棄式 non-root Worker。
- Secret redaction，且 Worker 不持有 Provider credential。
- Canonical Evidence hash 與 append-oriented Audit record。
- Project isolation、bounded retry、idempotency 與 fail-closed error。

## 非目標

Phase 0 不宣稱鑑識不可否認性、惡意多租戶隔離，或安全執行不可信第三方 Plugin。
