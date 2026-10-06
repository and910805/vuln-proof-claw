"""Tests for the one fact taken from a response body.

The oracles never see a body. This module is the single exception, and what it is
allowed to return is a boolean, so these tests are mostly about what it must *not*
decide.
"""

from __future__ import annotations

import pytest

from vuln_proof_claw.agent.bodyfacts import declares_failure

JSON = "application/json; charset=utf-8"


def test_the_case_this_exists_for() -> None:
    """A zero-trust platform's /api/me, answered anonymously: HTTP 200, every identity
    field null, and the body saying it refused. The status line says success."""
    body = (
        '{"token":null,"role":null,"id":null,"email":null,"displayName":null,'
        '"clientType":2,"success":false,"message":"authentication required"}'
    )

    assert declares_failure(body, content_type=JSON) is True


@pytest.mark.parametrize(
    "body",
    [
        '{"success": false}',
        '{"ok": false}',
        '{"status": "error"}',
        '{"status": "Failed"}',
        '{"result": "DENIED"}',
        '{"state": "unauthorized"}',
    ],
)
def test_the_shapes_an_application_refuses_in(body: str) -> None:
    assert declares_failure(body, content_type=JSON) is True


@pytest.mark.parametrize(
    "body",
    [
        '{"success": true}',
        '{"status": "Success"}',
        '{"data": [], "status": "ok"}',
        '{"message": "an error occurred while loading your profile"}',
        '{"errors": []}',
    ],
)
def test_a_body_that_does_not_declare_failure(body: str) -> None:
    """A message merely containing the word is not a declaration. Treating it as one
    would suppress a real finding on an endpoint whose data mentions errors."""
    assert declares_failure(body, content_type=JSON) is False


def test_an_unparseable_body_declares_nothing() -> None:
    """The absence of a declared failure is not a declared success, and guessing turns
    this from a fact into an interpretation."""
    assert declares_failure("<html><body>no</body></html>", content_type=JSON) is False
    assert declares_failure(b"\xff\xfe binary", content_type=JSON) is False
    assert declares_failure("", content_type=JSON) is False
    assert declares_failure(None) is False


def test_a_json_array_declares_nothing() -> None:
    assert declares_failure('[{"success": false}]', content_type=JSON) is False


def test_a_non_json_content_type_is_not_searched() -> None:
    """A page that happens to contain the text is not an application saying no."""
    assert declares_failure('{"success": false}', content_type="text/html") is False


def test_a_large_body_is_not_an_envelope() -> None:
    """Scanning a megabyte of content for a status word would be reading the content,
    which is the thing this module exists not to do."""
    padding = "x" * 5000
    assert declares_failure(f'{{"success": false, "pad": "{padding}"}}', content_type=JSON) is False


def test_the_content_type_may_be_absent() -> None:
    """Not every transport reports one, and refusing to look would lose the fact."""
    assert declares_failure('{"success": false}') is True


def test_an_error_envelope_in_another_vocabulary() -> None:
    """A mail platform's POST /auth/token with an empty body: HTTP 200 and
    {"ERROR_CODE": "ERR_01", "ERROR_MESSAGE": "Authentication failed"}. The
    application refused; it simply does not use the words the other checks know."""
    body = '{"ERROR_CODE":"ERR_01","ERROR_MESSAGE":"Authentication failed"}'

    assert declares_failure(body, content_type=JSON) is True


@pytest.mark.parametrize(
    "body",
    [
        '{"errorCode": "E42"}',
        '{"errcode": "x", "errmsg": "nope"}',
        '{"error": "forbidden", "code": 403}',
    ],
)
def test_the_same_envelope_however_it_is_spelled(body: str) -> None:
    assert declares_failure(body, content_type=JSON) is True


def test_an_error_alongside_data_is_not_an_envelope() -> None:
    """Suppressing this would hide a real finding to avoid a false one, which is the
    wrong trade in a tool whose suppressions nobody reads."""
    body = '{"error": "partial", "users": [{"id": 1}]}'

    assert declares_failure(body, content_type=JSON) is False


@pytest.mark.parametrize(
    "body",
    ['{"errors": []}', '{"error": ""}', '{"error": null}', '{"error_count": 0}'],
)
def test_an_application_saying_there_was_no_error(body: str) -> None:
    assert declares_failure(body, content_type=JSON) is False


def test_an_envelope_with_no_error_field_declares_nothing() -> None:
    """{"status": "ok", "code": 200} is an outcome, and the outcome is success."""
    assert declares_failure('{"status": "ok", "code": 200}', content_type=JSON) is False


@pytest.mark.parametrize(
    "body",
    [
        # The nine exchanges behind a submitted IT-08 report. Every one of them must
        # keep triggering: a change that widens what counts as "the application
        # refused" can retract a finding already sent to a vendor, and nothing in the
        # pipeline would say so.
        '{"Data":[],"Status":"Success","ErrorMessage":""}',
        '{"Status":"Error","ErrorMessage":"adminUuid is not existing"}',
        '{"Status":"Error","ErrorMessage":"Request data is not complete."}',
    ],
)
def test_a_submitted_finding_is_not_retracted_by_this(body: str) -> None:
    """Two of these say Status: Error -- and they are the finding. The endpoint reached
    its own validation layer without being authenticated, which is the defect; it
    complaining about the parameters afterwards is the proof, not a refusal."""
    assert declares_failure(body, content_type=JSON) is False
