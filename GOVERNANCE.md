# Governance

[繁體中文](GOVERNANCE.zh-TW.md) | **English**

## Roles

- **Maintainers** approve releases, architecture, security policy, and contributor access.
- **Reviewers** provide domain review but cannot approve their own changes.
- **Contributors** submit issues, documentation, tests, and code under the project policies.

## Decisions

Routine decisions use reviewed pull requests. Architecture, security boundaries, public API changes, and governance changes require a documented proposal and maintainer approval.

Security invariants take priority over compatibility and delivery speed. No LLM output, plugin, playbook, or user prompt can override a code-enforced deny rule.

## Releases

Maintainers approve version numbers and release notes. Releases must identify known limitations, migration requirements, security-relevant changes, and verification status.

## Project assets

Repository access, package names, signing keys, domains, and release credentials are project assets. Access follows least privilege and must be removed when no longer required.

## Amendments

Governance changes require synchronized English and Traditional Chinese documents and a public pull request.
