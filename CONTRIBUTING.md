# Contributing

[繁體中文](CONTRIBUTING.zh-TW.md) | **English**

Thank you for improving vuln-proof-claw.

## Before starting

1. Search existing issues and discussions.
2. Open an issue before large architectural, security-policy, schema, or dependency changes.
3. Keep changes focused and independently testable.
4. Never include secrets, customer data, unauthorized test results, or unlicensed content.

## Development checks

Use commands allowed by your endpoint security policy. This repository supports module execution:

```bash
python -m ruff check .
python -m mypy src
python -m pytest
```

Authorized testing may legitimately trigger EDR and other defensive alerts. Coordinate
alert expectations with the system owner; do not bypass, disable, tamper with, or design
around EDR, AppLocker, sandbox, or organizational security controls.

## Pull requests

- Explain the problem, design choice, security impact, and verification performed.
- Add tests for behavior changes.
- Update English and `.zh-TW.md` documentation together.
- Keep public APIs backward compatible or document the migration.
- Sign commits with the DCO sign-off: `git commit -s`.

## Commit style

Use concise conventional prefixes such as `build:`, `docs:`, `feat:`, `fix:`, `refactor:`, `test:`, and `ci:`.

## Security-sensitive changes

Changes to scope enforcement, approvals, worker isolation, command execution, credential handling, or evidence integrity require focused tests and maintainer review.
