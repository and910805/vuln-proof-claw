"""Tests for recursive secret redaction."""

from pydantic import SecretStr

from vuln_proof_claw.config.redaction import REDACTED, redact


def test_redacts_nested_sensitive_keys_and_secret_types() -> None:
    value = {
        "api_key": "sk-example",
        "nested": {
            "password": "hunter2",
            "safe": "visible",
            "secret_type": SecretStr("hidden"),
        },
    }

    result = redact(value)

    assert result["api_key"] == REDACTED
    assert result["nested"]["password"] == REDACTED
    assert result["nested"]["secret_type"] == REDACTED
    assert result["nested"]["safe"] == "visible"


def test_redacts_inline_authorization_values() -> None:
    value = "Authorization: Bearer abc.def.ghi and Basic dXNlcjpwYXNz"

    result = redact(value)

    assert "abc.def.ghi" not in result
    assert "dXNlcjpwYXNz" not in result
    assert result.count(REDACTED) == 2


def test_preserves_collection_shapes() -> None:
    result = redact(("safe", ["value", {"token": "secret"}]))

    assert result == ("safe", ["value", {"token": REDACTED}])
