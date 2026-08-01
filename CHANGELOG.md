# Changelog

[繁體中文](CHANGELOG.zh-TW.md) | **English**

Notable changes are documented here. The format follows Keep a Changelog concepts and semantic versioning once versioned releases begin.

## Unreleased

## [0.0.3] - 2026-08-01

### Added

- Persisted normalized allow/deny scope policies for time-bounded engagements.
- Added engagement create, list, detail, and offline scope-evaluation API contracts.
- Added metadata-only JSON and Markdown engagement reports.
- Added Alembic revision `0002_engagement_scopes` and Evidence Core preview documentation.

### Security

- Scope evaluation remains offline and flags hostname decisions for execution-time DNS rechecks.
- Reports exclude raw evidence and target execution remains fail-closed.

## [0.0.2] - 2026-08-01

### Added

- Added a root `VERSION` marker and consistency coverage for Python and Web package versions.
- Displayed the running API version in the Web console.

### Changed

- Updated local setup instructions to install a security-supported `pip` before auditing dependencies.
- Normalized generated Web asset line endings for reproducible Windows builds.

## [0.0.1] - 2026-07-30

### Added

- Independently designed bilingual platform specification.
- Bilingual Phase 0 implementation plan.
- Python package and initial CLI bootstrap.
- Initial bilingual open-source governance documents.
- Bundled bilingual React/TypeScript Web console with live readiness, dashboard counts, and project creation.
- Versioned dashboard and project REST API contracts.

### Security

- Documented EDR-respecting development policy.
- Defined authorized-use, private-reporting, scope, approval, worker-isolation, and evidence-integrity expectations.
- Kept unavailable target execution visibly locked and enforced all authority on the server side.
