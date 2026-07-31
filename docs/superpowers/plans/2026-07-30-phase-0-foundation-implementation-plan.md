# Phase 0 Foundation Implementation Plan

**English** | [繁體中文](2026-07-30-phase-0-foundation-implementation-plan.zh-TW.md)

**Status:** Approved for implementation

**Design source:** [Platform design](../specs/2026-07-30-vuln-proof-claw-platform-design.md)

## Goal

Deliver a reproducible, bilingual, testable project foundation that starts through Docker Compose and exposes a CLI, REST health endpoint, PostgreSQL connection, domain primitives, policy skeleton, evidence skeleton, and CI quality gates.

Phase 0 does not execute security scans or call an LLM.

## Definition of done

- `docker compose up --build` starts the API and PostgreSQL.
- `vuln-proof-claw doctor` reports configuration, API, database, and Docker readiness.
- `GET /api/v1/health/live` and `GET /api/v1/health/ready` return documented schemas.
- Alembic can upgrade a new database to head.
- Core domain and action-state tests pass.
- English and Traditional Chinese contributor documentation exists.
- CI runs lint, type checking, unit tests, dependency audit, and image build.
- No target-facing tool or arbitrary shell capability exists in Phase 0.

## Work sequence

### Task 1 — Python project and developer tooling

**Files**

- `pyproject.toml`
- `.python-version`
- `.editorconfig`
- `.gitignore`
- `src/vuln_proof_claw/__init__.py`
- `src/vuln_proof_claw/__main__.py`
- `tests/__init__.py`

**Implementation**

1. Configure Python 3.12 and Hatchling.
2. Define runtime dependencies for Typer, FastAPI, Pydantic Settings, SQLAlchemy, Alembic, HTTPX, structlog, and psycopg.
3. Define development dependencies for pytest, pytest-asyncio, Ruff, mypy, coverage, pip-audit, and Bandit.
4. Register the `vuln-proof-claw` console entry point.
5. Enable strict mypy settings and deterministic pytest configuration.

**Verification**

```bash
python -m pip install -e ".[dev]"
python -m vuln_proof_claw --help
ruff check .
mypy src
pytest
```

**Commit**

`build: initialize Python project`

### Task 2 — Bilingual repository governance

**Files**

- `LICENSE`
- `SECURITY.md`
- `SECURITY.zh-TW.md`
- `CONTRIBUTING.md`
- `CONTRIBUTING.zh-TW.md`
- `CODE_OF_CONDUCT.md`
- `CODE_OF_CONDUCT.zh-TW.md`
- `GOVERNANCE.md`
- `GOVERNANCE.zh-TW.md`
- `ROADMAP.md`
- `ROADMAP.zh-TW.md`
- `CHANGELOG.md`
- `CHANGELOG.zh-TW.md`
- `THREAT_MODEL.md`
- `THREAT_MODEL.zh-TW.md`
- `ARCHITECTURE.md`
- `ARCHITECTURE.zh-TW.md`

**Implementation**

1. Add the MIT License.
2. Document responsible vulnerability reporting.
3. Define contributor workflow, DCO sign-off, review expectations, and bilingual-document rules.
4. Publish the approved architecture and roadmap in concise public documents.
5. Document Phase 0 threat boundaries and non-goals.

**Verification**

```bash
python scripts/check_bilingual_docs.py
rg -n "TBD|TODO|FIXME" README*.md *.md docs
```

**Commit**

`docs: add bilingual project governance`

### Task 3 — Configuration and secret handling

**Files**

- `src/vuln_proof_claw/config/models.py`
- `src/vuln_proof_claw/config/settings.py`
- `src/vuln_proof_claw/config/redaction.py`
- `.env.example`
- `tests/config/test_settings.py`
- `tests/config/test_redaction.py`

**Implementation**

1. Create immutable Pydantic settings for application, database, API, Docker, logging, and provider placeholders.
2. Use the `VULN_PROOF_CLAW_` environment prefix.
3. Prevent secret values from appearing in representations or structured logs.
4. Validate unsafe production combinations, including wildcard API binding without authentication readiness.
5. Keep provider credentials out of worker settings.

**Verification**

```bash
pytest tests/config -q
mypy src/vuln_proof_claw/config
```

**Commit**

`feat: add typed configuration and secret redaction`

### Task 4 — Structured logging and identifiers

**Files**

- `src/vuln_proof_claw/observability/logging.py`
- `src/vuln_proof_claw/domain/identifiers.py`
- `tests/observability/test_logging.py`
- `tests/domain/test_identifiers.py`

**Implementation**

1. Configure JSON and human-readable logging modes.
2. Bind request, project, engagement, flow, task, action, and worker IDs.
3. Generate sortable UUIDv7-compatible identifiers without embedding user data.
4. Redact protected fields before serialization.

**Verification**

```bash
pytest tests/observability tests/domain/test_identifiers.py -q
```

**Commit**

`feat: add structured logging and domain identifiers`

### Task 5 — Domain primitives and action state machine

**Files**

- `src/vuln_proof_claw/domain/enums.py`
- `src/vuln_proof_claw/domain/models.py`
- `src/vuln_proof_claw/domain/action_state.py`
- `src/vuln_proof_claw/domain/errors.py`
- `tests/domain/test_action_state.py`
- `tests/domain/test_models.py`

**Implementation**

1. Define Project, Engagement, Flow, Task, Action, Evidence, Artifact, Approval, and Finding identifiers and value objects.
2. Define risk levels L0 through L4.
3. Implement the approved Action transition table.
4. Reject invalid or terminal-state transitions.
5. Keep domain code independent of FastAPI, SQLAlchemy, Docker, and LLM SDKs.

**Verification**

```bash
pytest tests/domain -q
```

**Commit**

`feat: define core domain and action lifecycle`

### Task 6 — PostgreSQL persistence and migrations

**Files**

- `src/vuln_proof_claw/persistence/base.py`
- `src/vuln_proof_claw/persistence/session.py`
- `src/vuln_proof_claw/persistence/models.py`
- `src/vuln_proof_claw/persistence/repositories.py`
- `alembic.ini`
- `migrations/env.py`
- `migrations/versions/0001_initial.py`
- `tests/persistence/test_migrations.py`
- `tests/persistence/test_repositories.py`

**Implementation**

1. Map Phase 0 domain entities without leaking ORM types into the domain layer.
2. Store timestamps in UTC.
3. Add optimistic version columns where concurrent transitions matter.
4. Add indexes for engagement, flow, action status, and evidence lookup.
5. Test upgrade from an empty PostgreSQL database.

**Verification**

```bash
alembic upgrade head
pytest tests/persistence -q
```

**Commit**

`feat: add PostgreSQL persistence and initial migration`

### Task 7 — Policy and approval skeleton

**Files**

- `src/vuln_proof_claw/policy/scope.py`
- `src/vuln_proof_claw/policy/risk.py`
- `src/vuln_proof_claw/policy/approval.py`
- `src/vuln_proof_claw/policy/decision.py`
- `tests/policy/test_scope.py`
- `tests/policy/test_risk.py`
- `tests/policy/test_approval.py`

**Implementation**

1. Normalize hostname, IP, CIDR, port, URL path, and scheme inputs.
2. Define allow, approval-required, and deny decisions.
3. Bind Approval to engagement, normalized action, parameter digest, expiry, and use count.
4. Reject replay after protected parameters change.
5. Implement Phase 0 permanent-deny placeholders without executing tools.

**Verification**

```bash
pytest tests/policy -q
```

**Commit**

`feat: add scope and approval policy core`

### Task 8 — Evidence integrity skeleton

**Files**

- `src/vuln_proof_claw/evidence/canonical.py`
- `src/vuln_proof_claw/evidence/hash_chain.py`
- `src/vuln_proof_claw/evidence/models.py`
- `src/vuln_proof_claw/evidence/store.py`
- `tests/evidence/test_canonical.py`
- `tests/evidence/test_hash_chain.py`

**Implementation**

1. Define deterministic canonical metadata encoding.
2. Implement SHA-256 chaining over previous hash, metadata, and raw bytes.
3. Verify a complete chain and identify the first invalid record.
4. Keep report redaction separate from raw evidence.
5. Use an in-memory store in unit tests and a PostgreSQL index interface for later phases.

**Verification**

```bash
pytest tests/evidence -q
```

**Commit**

`feat: add tamper-evident evidence primitives`

### Task 9 — FastAPI application and health contracts

**Files**

- `src/vuln_proof_claw/api/app.py`
- `src/vuln_proof_claw/api/dependencies.py`
- `src/vuln_proof_claw/api/routes/health.py`
- `src/vuln_proof_claw/api/schemas/health.py`
- `tests/api/test_health.py`

**Implementation**

1. Create an application factory with explicit lifespan handling.
2. Implement liveness without dependency checks.
3. Implement readiness checks for configuration and database connectivity.
4. Return stable versioned response schemas.
5. Generate OpenAPI without exposing secrets.

**Verification**

```bash
pytest tests/api -q
uvicorn vuln_proof_claw.api.app:create_app --factory
```

**Commit**

`feat: add API application and health endpoints`

### Task 10 — CLI foundation and doctor command

**Files**

- `src/vuln_proof_claw/cli/app.py`
- `src/vuln_proof_claw/cli/doctor.py`
- `src/vuln_proof_claw/cli/version.py`
- `tests/cli/test_cli.py`
- `tests/cli/test_doctor.py`

**Implementation**

1. Add `--help`, `--version`, and `doctor`.
2. Check configuration, API reachability, database readiness, and Docker availability.
3. Emit human-readable output by default and JSON with `--json`.
4. Never print credential values.
5. Return nonzero exit status when required dependencies are unavailable.

**Verification**

```bash
vuln-proof-claw --help
vuln-proof-claw doctor --json
pytest tests/cli -q
```

**Commit**

`feat: add CLI and environment doctor`

### Task 11 — Docker Compose and worker protocol skeleton

**Files**

- `Dockerfile`
- `compose.yaml`
- `docker/api-entrypoint.sh`
- `docker/worker/Dockerfile`
- `src/vuln_proof_claw/execution/protocol.py`
- `src/vuln_proof_claw/execution/manager.py`
- `tests/execution/test_protocol.py`
- `tests/integration/test_compose_health.py`

**Implementation**

1. Build a non-root API image.
2. Start API and PostgreSQL with health checks.
3. Define a versioned worker request/response protocol.
4. Implement a Worker Manager interface without target-facing execution.
5. Ensure worker containers do not mount the host home directory.
6. Document the Docker socket threat and restrict access to the manager.

**Verification**

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

### Task 12 — CI, supply-chain checks, and bilingual-doc check

**Files**

- `.github/workflows/ci.yml`
- `.github/workflows/container.yml`
- `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/pull_request_template.md`
- `scripts/check_bilingual_docs.py`
- `tests/scripts/test_check_bilingual_docs.py`

**Implementation**

1. Run Ruff, mypy, pytest, coverage, pip-audit, and Bandit.
2. Build the Docker image and scan it with Trivy.
3. Generate an SBOM artifact.
4. Fail CI when a maintained English document lacks its `.zh-TW.md` pair.
5. Add bilingual issue and pull-request guidance.
6. Pin GitHub Actions by immutable commit SHA before v1.0.

**Verification**

```bash
python scripts/check_bilingual_docs.py
ruff check .
mypy src
pytest --cov=vuln_proof_claw --cov-report=term-missing
pip-audit
bandit -r src
docker build .
```

**Commit**

`ci: add quality and supply-chain gates`

## Final Phase 0 verification

Run from a clean clone:

```bash
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest --cov=vuln_proof_claw --cov-report=term-missing
python scripts/check_bilingual_docs.py
docker compose config
docker compose up --build -d
vuln-proof-claw doctor
curl --fail http://127.0.0.1:8080/api/v1/health/ready
docker compose down --volumes
```

Record the results in the Phase 0 release notes in both languages.
