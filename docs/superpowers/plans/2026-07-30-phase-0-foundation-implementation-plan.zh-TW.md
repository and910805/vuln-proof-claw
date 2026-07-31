# Phase 0 基礎建設實作計畫

[English](2026-07-30-phase-0-foundation-implementation-plan.md) | **繁體中文**

**狀態：** 已核准進入實作

**設計來源：** [平台設計](../specs/2026-07-30-vuln-proof-claw-platform-design.zh-TW.md)

## 目標

交付一套可重現、具雙語文件且可測試的專案基礎。系統可透過 Docker Compose 啟動，並提供 CLI、REST health endpoint、PostgreSQL 連線、領域原語、Policy 骨架、Evidence 骨架與 CI quality gate。

Phase 0 不執行安全掃描，也不呼叫 LLM。

## 完成條件

- `docker compose up --build` 可啟動 API 與 PostgreSQL。
- `vuln-proof-claw doctor` 可回報設定、API、資料庫與 Docker readiness。
- `GET /api/v1/health/live` 與 `GET /api/v1/health/ready` 回傳文件化 schema。
- Alembic 可將全新資料庫升級至 head。
- 核心 domain 與 Action state test 通過。
- 英文與繁體中文 contributor 文件齊全。
- CI 執行 lint、type check、unit test、dependency audit 與 image build。
- Phase 0 不提供任何目標端工具或任意 shell capability。

## 工作順序

### Task 1 — Python 專案與開發工具

**檔案**

- `pyproject.toml`
- `.python-version`
- `.editorconfig`
- `.gitignore`
- `src/vuln_proof_claw/__init__.py`
- `src/vuln_proof_claw/__main__.py`
- `tests/__init__.py`

**實作**

1. 設定 Python 3.12 與 Hatchling。
2. 加入 Typer、FastAPI、Pydantic Settings、SQLAlchemy、Alembic、HTTPX、structlog 與 psycopg。
3. 加入 pytest、pytest-asyncio、Ruff、mypy、coverage、pip-audit 與 Bandit。
4. 註冊 `vuln-proof-claw` console entry point。
5. 啟用嚴格 mypy 與確定性的 pytest 設定。

**驗證**

```bash
python -m pip install -e ".[dev]"
python -m vuln_proof_claw --help
ruff check .
mypy src
pytest
```

**Commit**

`build: initialize Python project`

### Task 2 — 雙語開源治理

**檔案**

- `LICENSE`
- `SECURITY.md` / `SECURITY.zh-TW.md`
- `CONTRIBUTING.md` / `CONTRIBUTING.zh-TW.md`
- `CODE_OF_CONDUCT.md` / `CODE_OF_CONDUCT.zh-TW.md`
- `GOVERNANCE.md` / `GOVERNANCE.zh-TW.md`
- `ROADMAP.md` / `ROADMAP.zh-TW.md`
- `CHANGELOG.md` / `CHANGELOG.zh-TW.md`
- `THREAT_MODEL.md` / `THREAT_MODEL.zh-TW.md`
- `ARCHITECTURE.md` / `ARCHITECTURE.zh-TW.md`

**實作**

1. 加入 MIT License。
2. 文件化負責任的漏洞通報方式。
3. 定義 contributor workflow、DCO、review expectation 與雙語文件規則。
4. 以簡潔公開文件發布已核准架構與 Roadmap。
5. 文件化 Phase 0 threat boundary 與 non-goal。

**驗證**

```bash
python scripts/check_bilingual_docs.py
rg -n "TBD|TODO|FIXME" README*.md *.md docs
```

**Commit**

`docs: add bilingual project governance`

### Task 3 — 設定與 Secret 處理

**檔案**

- `src/vuln_proof_claw/config/models.py`
- `src/vuln_proof_claw/config/settings.py`
- `src/vuln_proof_claw/config/redaction.py`
- `.env.example`
- `tests/config/test_settings.py`
- `tests/config/test_redaction.py`

**實作**

1. 建立 application、database、API、Docker、logging 與 Provider placeholder 的 immutable Pydantic settings。
2. 使用 `VULN_PROOF_CLAW_` 環境變數前綴。
3. 防止 secret 出現在 representation 或 structured log。
4. 阻擋不安全的 production 設定組合。
5. Worker settings 不得包含 Provider credential。

**驗證**

```bash
pytest tests/config -q
mypy src/vuln_proof_claw/config
```

**Commit**

`feat: add typed configuration and secret redaction`

### Task 4 — Structured logging 與 Identifier

**檔案**

- `src/vuln_proof_claw/observability/logging.py`
- `src/vuln_proof_claw/domain/identifiers.py`
- `tests/observability/test_logging.py`
- `tests/domain/test_identifiers.py`

**實作**

1. 提供 JSON 與人類可讀 logging mode。
2. 綁定 request、project、engagement、flow、task、action 與 worker ID。
3. 產生可排序且不包含使用者資料的 UUIDv7-compatible ID。
4. 在 serialization 前 redaction 受保護欄位。

**驗證**

```bash
pytest tests/observability tests/domain/test_identifiers.py -q
```

**Commit**

`feat: add structured logging and domain identifiers`

### Task 5 — Domain 原語與 Action state machine

**檔案**

- `src/vuln_proof_claw/domain/enums.py`
- `src/vuln_proof_claw/domain/models.py`
- `src/vuln_proof_claw/domain/action_state.py`
- `src/vuln_proof_claw/domain/errors.py`
- `tests/domain/test_action_state.py`
- `tests/domain/test_models.py`

**實作**

1. 定義 Project、Engagement、Flow、Task、Action、Evidence、Artifact、Approval 與 Finding value object。
2. 定義 L0 至 L4 risk level。
3. 實作核准的 Action transition table。
4. 拒絕無效或 terminal state transition。
5. Domain code 不依賴 FastAPI、SQLAlchemy、Docker 或 LLM SDK。

**驗證**

```bash
pytest tests/domain -q
```

**Commit**

`feat: define core domain and action lifecycle`

### Task 6 — PostgreSQL persistence 與 Migration

**檔案**

- `src/vuln_proof_claw/persistence/base.py`
- `src/vuln_proof_claw/persistence/session.py`
- `src/vuln_proof_claw/persistence/models.py`
- `src/vuln_proof_claw/persistence/repositories.py`
- `alembic.ini`
- `migrations/env.py`
- `migrations/versions/0001_initial.py`
- `tests/persistence/test_migrations.py`
- `tests/persistence/test_repositories.py`

**實作**

1. 對應 Phase 0 domain entity，不讓 ORM type 洩漏至 domain layer。
2. Timestamp 統一儲存 UTC。
3. 需要 concurrency control 的 entity 加入 optimistic version。
4. 為 Engagement、Flow、Action status 與 Evidence lookup 建立 index。
5. 測試從空白 PostgreSQL 執行 migration。

**驗證**

```bash
alembic upgrade head
pytest tests/persistence -q
```

**Commit**

`feat: add PostgreSQL persistence and initial migration`

### Task 7 — Policy 與 Approval 骨架

**檔案**

- `src/vuln_proof_claw/policy/scope.py`
- `src/vuln_proof_claw/policy/risk.py`
- `src/vuln_proof_claw/policy/approval.py`
- `src/vuln_proof_claw/policy/decision.py`
- `tests/policy/test_scope.py`
- `tests/policy/test_risk.py`
- `tests/policy/test_approval.py`

**實作**

1. 正規化 hostname、IP、CIDR、port、URL path 與 scheme。
2. 定義 allow、approval-required 與 deny decision。
3. Approval 綁定 Engagement、正規化 Action、parameter digest、expiry 與 use count。
4. 受保護參數變更後拒絕 replay。
5. 實作 Phase 0 permanent-deny placeholder，但不執行工具。

**驗證**

```bash
pytest tests/policy -q
```

**Commit**

`feat: add scope and approval policy core`

### Task 8 — Evidence integrity 骨架

**檔案**

- `src/vuln_proof_claw/evidence/canonical.py`
- `src/vuln_proof_claw/evidence/hash_chain.py`
- `src/vuln_proof_claw/evidence/models.py`
- `src/vuln_proof_claw/evidence/store.py`
- `tests/evidence/test_canonical.py`
- `tests/evidence/test_hash_chain.py`

**實作**

1. 定義 deterministic canonical metadata encoding。
2. 以 previous hash、metadata 與 raw bytes 實作 SHA-256 chain。
3. 驗證完整 chain 並找出第一筆無效 record。
4. Report redaction 與 raw Evidence 分離。
5. Unit test 使用 in-memory store，並保留 PostgreSQL index interface。

**驗證**

```bash
pytest tests/evidence -q
```

**Commit**

`feat: add tamper-evident evidence primitives`

### Task 9 — FastAPI application 與 Health contract

**檔案**

- `src/vuln_proof_claw/api/app.py`
- `src/vuln_proof_claw/api/dependencies.py`
- `src/vuln_proof_claw/api/routes/health.py`
- `src/vuln_proof_claw/api/schemas/health.py`
- `tests/api/test_health.py`

**實作**

1. 建立具有明確 lifespan handling 的 application factory。
2. Liveness 不執行 dependency check。
3. Readiness 檢查 configuration 與 database connectivity。
4. 回傳穩定且具版本的 response schema。
5. OpenAPI 不得暴露 secret。

**驗證**

```bash
pytest tests/api -q
uvicorn vuln_proof_claw.api.app:create_app --factory
```

**Commit**

`feat: add API application and health endpoints`

### Task 10 — CLI 基礎與 Doctor

**檔案**

- `src/vuln_proof_claw/cli/app.py`
- `src/vuln_proof_claw/cli/doctor.py`
- `src/vuln_proof_claw/cli/version.py`
- `tests/cli/test_cli.py`
- `tests/cli/test_doctor.py`

**實作**

1. 加入 `--help`、`--version` 與 `doctor`。
2. 檢查 configuration、API、database 與 Docker availability。
3. 預設人類可讀輸出，`--json` 提供 JSON。
4. 絕不輸出 credential value。
5. 必要 dependency unavailable 時回傳非零 exit code。

**驗證**

```bash
vuln-proof-claw --help
vuln-proof-claw doctor --json
pytest tests/cli -q
```

**Commit**

`feat: add CLI and environment doctor`

### Task 11 — Docker Compose 與 Worker protocol 骨架

**檔案**

- `Dockerfile`
- `compose.yaml`
- `docker/api-entrypoint.sh`
- `docker/worker/Dockerfile`
- `src/vuln_proof_claw/execution/protocol.py`
- `src/vuln_proof_claw/execution/manager.py`
- `tests/execution/test_protocol.py`
- `tests/integration/test_compose_health.py`

**實作**

1. 建立 non-root API image。
2. 以 health check 啟動 API 與 PostgreSQL。
3. 定義版本化 Worker request/response protocol。
4. 建立不具目標端執行能力的 Worker Manager interface。
5. Worker container 不掛載 host home directory。
6. 文件化 Docker socket threat，並限制只有 Manager 可存取。

**驗證**

```bash
docker compose config
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/api/v1/health/ready
docker compose down --volumes
pytest tests/execution tests/integration/test_compose_health.py -q
```

**Commit**

`feat: add Compose deployment and worker protocol`

### Task 12 — CI、Supply chain 與雙語文件檢查

**檔案**

- `.github/workflows/ci.yml`
- `.github/workflows/container.yml`
- `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/pull_request_template.md`
- `.github/pull_request_template.zh-TW.md`
- `scripts/__init__.py`
- `scripts/check_bilingual_docs.py`
- `tests/scripts/test_check_bilingual_docs.py`
- `tests/scripts/test_ci_configuration.py`

**實作**

1. 執行 Ruff、mypy、pytest、coverage、pip-audit 與 Bandit。
2. 建立 Docker image 並以 Trivy 掃描。
3. 產生 SBOM artifact。
4. 持續維護的英文文件缺少 `.zh-TW.md` 配對時 CI 失敗。
5. 加入雙語 Issue 與 Pull Request 指引。
6. v1.0 前將 GitHub Action 固定至 immutable commit SHA。

**驗證**

```bash
python scripts/check_bilingual_docs.py
python -m ruff check .
python -m mypy
python -m pytest --cov=vuln_proof_claw --cov-report=term-missing
python -m pip_audit
python -m bandit -r src
docker build .
```

**Commit**

`ci: add quality and supply-chain gates`

## Phase 0 最終驗證

從全新 clone 執行：

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy
python -m pytest --cov=vuln_proof_claw --cov-report=term-missing
python scripts/check_bilingual_docs.py
docker compose config
docker compose up --build -d
vuln-proof-claw doctor
curl --fail http://127.0.0.1:8080/api/v1/health/ready
docker compose down --volumes
```

將結果同時記錄於英文與繁體中文 Phase 0 release note。
