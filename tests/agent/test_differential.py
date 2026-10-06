"""Tests for the deterministic authorization oracles.

These matter more than most: the oracles are what stop the system reporting a
hallucinated finding. Each suppression path is tested explicitly, because a rule that
fires on a benign difference is worse than one that stays quiet — under the activity
rules a bad report costs one of only two 補正 chances.
"""

from __future__ import annotations

import pytest

from vuln_proof_claw.agent.differential import (
    ANONYMOUS,
    Identity,
    IdentityRole,
    OracleRule,
    ProbeResult,
    body_digest,
    check_denial_inconsistency,
    check_horizontal_privilege,
    check_missing_authentication,
    check_unauthenticated_access,
    check_vertical_privilege,
    evaluate_all,
)
from vuln_proof_claw.domain.errors import DomainValidationError

TARGET = "https://10.26.0.40:443/web/pkghub/files/42"
OWNER_BODY = body_digest(b'{"id":42,"owner":"account24","secret":"x"}' * 4)
OTHER_BODY = body_digest(b'{"error":"forbidden"}' * 4)
BIG = 400


def probe(  # noqa: PLR0913 - each field is one observable fact about one response
    identity: str,
    status: int,
    *,
    digest: str = OWNER_BODY,
    size: int = BIG,
    target: str = TARGET,
    content_type: str = "application/json",
) -> ProbeResult:
    return ProbeResult(
        identity=identity,
        method="GET",
        target=target,
        status_code=status,
        body_digest=digest,
        body_size=size,
        content_type=content_type,
    )


def test_identity_roles_are_ordered() -> None:
    assert IdentityRole.ANONYMOUS.rank < IdentityRole.USER.rank
    assert IdentityRole.USER.rank < IdentityRole.PRIVILEGED.rank
    assert Identity(name="account24").role is IdentityRole.USER


def test_an_identity_needs_a_name() -> None:
    with pytest.raises(DomainValidationError):
        Identity(name="  ")


def test_a_probe_rejects_negative_body_size() -> None:
    with pytest.raises(DomainValidationError):
        probe("a", 200, size=-1)


def test_probe_state_helpers() -> None:
    assert probe("a", 200).succeeded
    assert probe("a", 403).denied
    assert probe("a", 302).redirected
    assert not probe("a", 200, size=4).substantive


# --- horizontal privilege: the strongest signal ---------------------------------


def test_horizontal_privilege_fires_when_another_user_gets_the_same_body() -> None:
    verdict = check_horizontal_privilege(
        [probe("account24", 200), probe("account25", 200)],
        owner="account24",
        other="account25",
    )

    assert verdict
    assert verdict.rule is OracleRule.HORIZONTAL_PRIVILEGE
    assert "identical" in verdict.reason
    assert len(verdict.probes) == 2


def test_horizontal_privilege_stays_quiet_when_the_other_user_is_denied() -> None:
    verdict = check_horizontal_privilege(
        [probe("account24", 200), probe("account25", 403, digest=OTHER_BODY)],
        owner="account24",
        other="account25",
    )

    assert not verdict
    assert "correctly received 403" in verdict.reason


def test_horizontal_privilege_stays_quiet_on_different_content() -> None:
    verdict = check_horizontal_privilege(
        [probe("account24", 200), probe("account25", 200, digest=OTHER_BODY)],
        owner="account24",
        other="account25",
    )

    assert not verdict
    assert verdict.suppressed_by == "different_content"


def test_a_public_resource_is_not_reported_as_a_leak() -> None:
    """If anonymous gets it too, the resource is public — not leaked between users."""
    verdict = check_horizontal_privilege(
        [probe("account24", 200), probe("account25", 200), probe(ANONYMOUS, 200)],
        owner="account24",
        other="account25",
    )

    assert not verdict
    assert verdict.suppressed_by == "resource_is_public"


def test_a_tiny_shared_body_is_not_reported() -> None:
    """Two identities sharing an empty or error body proves nothing."""
    verdict = check_horizontal_privilege(
        [probe("account24", 200, size=8), probe("account25", 200, size=8)],
        owner="account24",
        other="account25",
    )

    assert not verdict
    assert verdict.suppressed_by == "owner_response_not_substantive"


def test_horizontal_privilege_needs_both_probes() -> None:
    verdict = check_horizontal_privilege(
        [probe("account24", 200)], owner="account24", other="account25"
    )

    assert not verdict
    assert "missing probe" in verdict.reason


# --- unauthenticated access ------------------------------------------------------


def test_unauthenticated_access_fires_on_identical_bodies() -> None:
    verdict = check_unauthenticated_access(
        [probe(ANONYMOUS, 200), probe("account24", 200)], authenticated="account24"
    )

    assert verdict
    assert verdict.rule is OracleRule.UNAUTHENTICATED_ACCESS


def test_unauthenticated_access_stays_quiet_when_anonymous_is_denied() -> None:
    verdict = check_unauthenticated_access(
        [probe(ANONYMOUS, 401, digest=OTHER_BODY), probe("account24", 200)],
        authenticated="account24",
    )

    assert not verdict
    assert "anonymous received 401" in verdict.reason


def test_unauthenticated_access_stays_quiet_on_a_login_redirect_page() -> None:
    verdict = check_unauthenticated_access(
        [probe(ANONYMOUS, 200, digest=OTHER_BODY), probe("account24", 200)],
        authenticated="account24",
    )

    assert not verdict
    assert verdict.suppressed_by == "different_content"


def test_unauthenticated_access_ignores_a_tiny_body() -> None:
    verdict = check_unauthenticated_access(
        [probe(ANONYMOUS, 200, size=4), probe("account24", 200, size=4)],
        authenticated="account24",
    )

    assert not verdict
    assert verdict.suppressed_by == "empty_or_tiny_body"


# --- vertical privilege ----------------------------------------------------------


def test_vertical_privilege_fires_when_a_user_reaches_an_admin_body() -> None:
    verdict = check_vertical_privilege(
        [probe("account24", 200), probe("admin", 200)], lower="account24", higher="admin"
    )

    assert verdict
    assert verdict.rule is OracleRule.VERTICAL_PRIVILEGE


def test_vertical_privilege_requires_the_endpoint_to_be_demonstrably_privileged() -> None:
    """If the admin identity did not get content either, the endpoint is just broken."""
    verdict = check_vertical_privilege(
        [probe("account24", 200), probe("admin", 500, size=0)],
        lower="account24",
        higher="admin",
    )

    assert not verdict
    assert verdict.suppressed_by == "endpoint_not_demonstrably_privileged"


def test_vertical_privilege_stays_quiet_when_the_user_is_denied() -> None:
    verdict = check_vertical_privilege(
        [probe("account24", 403, digest=OTHER_BODY), probe("admin", 200)],
        lower="account24",
        higher="admin",
    )

    assert not verdict


# --- denial inconsistency --------------------------------------------------------


def test_denial_inconsistency_flags_404_versus_403() -> None:
    verdict = check_denial_inconsistency(
        [probe("account24", 403, digest=OTHER_BODY), probe("account25", 404, digest=OTHER_BODY)]
    )

    assert verdict
    assert "existence is distinguishable" in verdict.reason


def test_correct_authorization_is_never_flagged_as_inconsistent() -> None:
    """Owner allowed, stranger denied: that is the control working, not a defect.

    Firing here would emit one false line per properly protected endpoint and bury
    any real finding.
    """
    verdict = check_denial_inconsistency(
        [probe("account24", 200), probe("account25", 403, digest=OTHER_BODY)]
    )

    assert not verdict
    assert verdict.suppressed_by == "authorization_working_as_intended"


def test_denial_inconsistency_stays_quiet_when_everyone_agrees() -> None:
    verdict = check_denial_inconsistency(
        [probe("account24", 403, digest=OTHER_BODY), probe("account25", 403, digest=OTHER_BODY)]
    )

    assert not verdict
    assert "consistent" in verdict.reason


def test_denial_inconsistency_needs_two_probes() -> None:
    assert not check_denial_inconsistency([probe("account24", 200)])


# --- orchestration ---------------------------------------------------------------


def test_evaluate_all_runs_the_applicable_rules() -> None:
    verdicts = evaluate_all(
        [
            probe(ANONYMOUS, 403, digest=OTHER_BODY),
            probe("account24", 200),
            probe("account25", 200),
        ],
        owner="account24",
        other="account25",
    )
    rules = {verdict.rule for verdict in verdicts}

    assert OracleRule.HORIZONTAL_PRIVILEGE in rules
    assert OracleRule.UNAUTHENTICATED_ACCESS in rules
    assert OracleRule.VERTICAL_PRIVILEGE not in rules  # no privileged identity supplied
    assert any(v.triggered and v.rule is OracleRule.HORIZONTAL_PRIVILEGE for v in verdicts)


def test_a_verdict_summarises_itself_for_an_operator() -> None:
    verdict = check_horizontal_privilege(
        [probe("account24", 200), probe("account25", 200)],
        owner="account24",
        other="account25",
    )

    assert verdict.as_summary().startswith("[TRIGGERED] horizontal_privilege")


def test_the_same_probes_always_produce_the_same_verdict() -> None:
    """Determinism is the property that makes a verdict reproducible by a reviewer."""
    probes = [
        probe("account24", 200),
        probe("account25", 200),
        probe(ANONYMOUS, 403, digest=OTHER_BODY),
    ]

    first = check_horizontal_privilege(probes, owner="account24", other="account25")
    second = check_horizontal_privilege(
        list(reversed(probes)), owner="account24", other="account25"
    )

    assert first.triggered == second.triggered
    assert first.reason == second.reason


# --- missing authentication -------------------------------------------------------
#
# The cases below are the responses actually observed on a live target, kept verbatim
# so a regression would be caught against reality rather than against an invention.


def anon(
    status: int,
    size: int = BIG,
    digest: str = OWNER_BODY,
    content_type: str = "application/json",
) -> ProbeResult:
    return probe(
        ANONYMOUS, status, size=size, digest=digest, content_type=content_type
    )


def test_an_unauthenticated_success_is_reported() -> None:
    """Observed: POST /api/getUserMenuList -> 200 {"Status":"Success"}"""
    verdict = check_missing_authentication(anon(200, size=94))

    assert verdict
    assert verdict.rule is OracleRule.MISSING_AUTHENTICATION
    assert "instead of 401/403" in verdict.reason


def test_a_business_layer_validation_error_is_reported() -> None:
    """Observed: POST /api/setDeviceMessage -> 400 "Request data is not complete."

    This is the case that proves the gap reaches write endpoints: the server answered
    in business terms rather than refusing an unauthenticated caller.
    """
    verdict = check_missing_authentication(anon(400, size=110))

    assert verdict


def test_a_business_layer_lookup_error_is_reported() -> None:
    """Observed: GET /api/getCompanyDisplay?adminUuid=... -> 500 "not existing"."""
    verdict = check_missing_authentication(anon(500, size=106))

    assert verdict


def test_an_application_shell_is_not_a_finding() -> None:
    """Observed: GET /redfish -> 200 text/html, the Vue app's own index.html.

    A single-page application answers every unmatched path with its shell. Read as a
    business-layer response it reports a finding on every path that does not exist —
    which is exactly what happened on the first live run.
    """
    verdict = check_missing_authentication(anon(200, size=810, content_type="text/html"))

    assert not verdict
    assert verdict.suppressed_by == "html_response_is_an_application_shell"


def test_the_html_suppression_tolerates_a_charset() -> None:
    verdict = check_missing_authentication(
        anon(200, size=810, content_type="text/html; charset=UTF-8")
    )

    assert not verdict


def test_a_json_answer_is_still_reported() -> None:
    """The suppression must not swallow the case it sits next to."""
    assert check_missing_authentication(
        anon(200, size=94, content_type="application/json")
    )


@pytest.mark.parametrize("status", [401, 403])
def test_a_proper_refusal_is_not_reported(status: int) -> None:
    verdict = check_missing_authentication(anon(status, size=40))

    assert not verdict
    assert "correctly refused" in verdict.reason


def test_a_login_redirect_is_not_reported() -> None:
    """A redirect is commonly the auth check doing its job."""
    verdict = check_missing_authentication(anon(302, size=0))

    assert not verdict
    assert verdict.suppressed_by == "redirect_may_be_an_auth_check"


@pytest.mark.parametrize("status", [404, 405])
def test_a_response_with_no_handler_proves_nothing(status: int) -> None:
    verdict = check_missing_authentication(anon(status, size=50))

    assert not verdict
    assert verdict.suppressed_by == "no_handler_reached"


def test_an_empty_server_error_is_not_a_business_answer() -> None:
    """A bare 500 is a crash, not evidence the business layer ran."""
    verdict = check_missing_authentication(anon(500, size=0))

    assert not verdict
    assert verdict.suppressed_by == "unhandled_error"


def test_the_rule_only_applies_to_anonymous_probes() -> None:
    verdict = check_missing_authentication(probe("account24", 200))

    assert not verdict
    assert "not anonymously" in verdict.reason


def test_evaluate_all_includes_the_rule_when_an_anonymous_probe_exists() -> None:
    verdicts = evaluate_all(
        [anon(200, size=94), probe("account24", 200)], owner="account24"
    )

    assert any(v.rule is OracleRule.MISSING_AUTHENTICATION and v.triggered for v in verdicts)


def test_evaluate_all_omits_the_rule_without_an_anonymous_probe() -> None:
    verdicts = evaluate_all(
        [probe("account24", 200), probe("account25", 200)],
        owner="account24",
        other="account25",
    )

    assert all(v.rule is not OracleRule.MISSING_AUTHENTICATION for v in verdicts)


@pytest.mark.parametrize(
    "content_type",
    [
        "application/javascript",
        "text/javascript; charset=UTF-8",
        "text/css",
        "image/png",
        "font/woff2",
        "image/svg+xml",
    ],
)
def test_a_static_file_is_not_evidence_that_authentication_is_missing(
    content_type: str,
) -> None:
    """Found on a live target: an anonymous sweep reported missing authentication on
    jquery.min.js, cookie.js and comm.js. The rule was satisfied exactly as written --
    200 with a body instead of 401 -- which is the trouble. Serving a file without a
    credential is how the web works, and three such candidates in a review queue have
    to be read and dismissed by a person before the real ones are reached."""
    verdict = check_missing_authentication(
        probe(ANONYMOUS, 200, content_type=content_type)
    )

    assert verdict.triggered is False
    assert verdict.suppressed_by == "static_asset_is_not_business_logic"


def test_the_media_type_decides_not_the_file_extension() -> None:
    """A path ending in .js proves nothing: an API that routes /api/report.js is an
    API. What the server said it was sending is the fact; the path is a guess."""
    verdict = check_missing_authentication(
        probe(ANONYMOUS, 200, target=f"{TARGET}/report.js", content_type="application/json")
    )

    assert verdict.triggered is True


def test_an_api_answer_still_triggers() -> None:
    """The suppression must not quietly swallow the rule it guards."""
    assert check_missing_authentication(probe(ANONYMOUS, 200)).triggered is True


@pytest.mark.parametrize(
    ("content_type", "suppression"),
    [
        ("application/javascript", "static_asset_is_not_business_logic"),
        ("image/png", "static_asset_is_not_business_logic"),
        ("text/html", "html_response_is_an_application_shell"),
    ],
)
def test_a_file_served_to_everyone_is_not_improper_access_control(
    content_type: str, suppression: str
) -> None:
    """Identical bodies are the whole signal for this rule, and a file the server hands
    to everyone is identical to everyone by design. The hour after the missing-auth
    rule learned this, an anonymous sweep produced eleven candidates on one target:
    eight webpack chunks, a logo, and the application shell."""
    verdict = check_unauthenticated_access(
        (
            probe(ANONYMOUS, 200, digest=OWNER_BODY, content_type=content_type),
            probe("account_a", 200, digest=OWNER_BODY, content_type=content_type),
        ),
        authenticated="account_a",
    )

    assert verdict.triggered is False
    assert verdict.suppressed_by == suppression


def test_an_api_body_shared_with_anonymous_still_triggers() -> None:
    """The suppression must not swallow the rule it guards."""
    verdict = check_unauthenticated_access(
        (
            probe(ANONYMOUS, 200, digest=OWNER_BODY, content_type="application/json"),
            probe("account_a", 200, digest=OWNER_BODY, content_type="application/json"),
        ),
        authenticated="account_a",
    )

    assert verdict.triggered is True


def test_both_rules_suppress_the_same_things() -> None:
    """Two copies of one judgement is how the second came to be missing it."""
    for content_type in ("application/javascript", "text/html", "font/woff2"):
        assert (
            check_missing_authentication(
                probe(ANONYMOUS, 200, content_type=content_type)
            ).suppressed_by
            == check_unauthenticated_access(
                (
                    probe(ANONYMOUS, 200, digest=OWNER_BODY, content_type=content_type),
                    probe("account_a", 200, digest=OWNER_BODY, content_type=content_type),
                ),
                authenticated="account_a",
            ).suppressed_by
        )
