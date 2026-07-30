# Architecture

[繁體中文](ARCHITECTURE.zh-TW.md) | **English**

## Direction

vuln-proof-claw uses a Python modular monolith for the control plane and disposable Docker containers for target-facing execution.

```text
CLI / REST API / future Web UI
              │
              ▼
      Python Control Plane
  Domain · Policy · Evidence
  Orchestration · Reporting
              │
       ┌──────┴──────┐
       ▼             ▼
  PostgreSQL    Worker Manager
                       │
                       ▼
              Disposable Worker
                       │
                       ▼
             Authorized Web/API
```

## Invariants

- Domain code does not depend on FastAPI, SQLAlchemy, Docker, or LLM SDKs.
- Target-facing actions require a scope decision before execution.
- High-risk actions require action-bound approval.
- Workers do not receive provider credentials or host home-directory mounts.
- Raw evidence is stored separately from redacted reports.
- Only the Verifier can promote a finding to `verified`.
- English and Traditional Chinese documentation remain paired.

## Phase 0

Phase 0 builds packaging, configuration, identifiers, domain state, persistence, policy/evidence primitives, health endpoints, CLI diagnostics, Docker Compose, worker protocol, and CI. It intentionally provides no target-facing security tools.

The detailed approved design and implementation plan are under `docs/superpowers/`.
