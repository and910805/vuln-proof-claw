"""Tests for recovering a surface by watching what an application actually requests.

Parsing a bundle only finds the idioms the parser knows. A recorded request has no
idiom, which is the whole reason this path exists, so what matters here is that the
recording is faithful, bounded, and safe to put in evidence.
"""

from __future__ import annotations

import asyncio
from unittest import mock

import pytest
from pydantic import SecretStr

from vuln_proof_claw.automation.browser import (
    _NEVER_FETCHED,
    _NOT_API,
    BrowserRunRequest,
    BrowserRunResult,
    BrowserVisitTimeoutError,
    IsolatedBrowserRunner,
    LoginInstruction,
    ObservedRequest,
    body_field_names,
    inventory,
)
from vuln_proof_claw.domain.errors import DomainValidationError


def observed(
    method: str = "GET",
    url: str = "https://10.26.0.40/web/clients",
    resource_type: str = "xhr",
    carried_body: bool = False,
) -> ObservedRequest:
    return ObservedRequest(
        method=method, url=url, resource_type=resource_type, carried_body=carried_body
    )


def result(*requests: ObservedRequest) -> BrowserRunResult:
    return BrowserRunResult(
        final_url="https://10.26.0.40/",
        title="RapixEngine",
        status_code=200,
        screenshot=b"",
        blocked_requests=(),
        observed_requests=requests,
    )


def test_a_path_is_taken_from_the_url() -> None:
    assert observed(url="https://h/web/clients").path == "/web/clients"
    assert observed(url="https://h/web/x?id=3").path == "/web/x?id=3"
    assert observed(url="https://h").path == "/"


def test_page_furniture_is_not_an_api_surface() -> None:
    """An inventory of stylesheets and fonts buries the endpoints that matter."""
    found = result(
        observed(url="https://h/web/clients", resource_type="xhr"),
        observed(url="https://h/app.css", resource_type="stylesheet"),
        observed(url="https://h/logo.png", resource_type="image"),
        observed(url="https://h/f.woff2", resource_type="font"),
    ).api_requests

    assert [request.path for request in found] == ["/web/clients"]


def test_a_script_is_kept_because_it_may_be_a_route() -> None:
    """Only the types a browser fetches to render are dropped; a fetch is not one."""
    found = result(
        observed(url="https://h/dist/main.js", resource_type="script"),
        observed(url="https://h/web/x", resource_type="fetch"),
    ).api_requests

    assert len(found) == 2


def test_a_polled_endpoint_is_counted_once() -> None:
    """An application polling sixty times has one endpoint, not sixty."""
    polled = [observed(url="https://h/web/status") for _ in range(60)]

    assert inventory(tuple(polled)) == (("GET", "/web/status"),)


def test_the_same_path_under_two_methods_is_two_endpoints() -> None:
    """GET /x and POST /x can behave completely differently."""
    found = inventory(
        (
            observed("GET", "https://h/web/x"),
            observed("POST", "https://h/web/x", carried_body=True),
        )
    )

    assert found == (("GET", "/web/x"), ("POST", "/web/x"))


def test_the_order_requests_were_made_in_is_kept() -> None:
    found = inventory(
        (
            observed(url="https://h/web/b"),
            observed(url="https://h/web/a"),
        )
    )

    assert found == (("GET", "/web/b"), ("GET", "/web/a"))


def test_a_method_is_normalised() -> None:
    assert inventory((observed("post", "https://h/web/x"),)) == (("POST", "/web/x"),)


def test_an_observation_records_that_a_body_existed_not_what_it_was() -> None:
    """A login's body is a credential; the shape is enough to classify an endpoint."""
    request = observed("POST", "https://h/web/session", carried_body=True)

    assert request.carried_body is True
    assert not hasattr(request, "body")
    assert "password" not in repr(request)


@pytest.mark.parametrize("resource_type", ["stylesheet", "image", "font", "media"])
def test_nothing_rendered_reaches_the_inventory(resource_type: str) -> None:
    assert result(observed(resource_type=resource_type)).api_requests == ()


def instruction(**overrides: object) -> LoginInstruction:
    defaults: dict[str, object] = {
        "login_url": "https://10.26.0.40/#/login",
        "username_selector": "#textbox-account",
        "password_selector": "#textbox-password",
        "submit_selector": "button.submit",
        "username": SecretStr("account"),
        "password": SecretStr("not-a-real-password"),
    }
    defaults.update(overrides)
    return LoginInstruction(**defaults)  # type: ignore[arg-type]


def test_a_form_behind_a_button_can_be_opened_first() -> None:
    """Observed live: the login page is a landing screen with one button, and the
    account and password fields only exist after it has been clicked."""
    assert instruction(open_selector="button.start").open_selector == "button.start"


def test_no_opener_means_no_extra_click() -> None:
    assert instruction().open_selector is None


def test_a_blank_opener_is_refused() -> None:
    """Unset means "no step". Blank means a mistake that would click nothing and then
    fail on fields that were never revealed, which reads as a broken selector."""
    with pytest.raises(DomainValidationError, match="selectors"):
        instruction(open_selector="   ")


def test_a_login_instruction_never_prints_its_credentials() -> None:
    rendered = repr(instruction(password=SecretStr("sup3r-s3cret-value")))

    assert "sup3r-s3cret-value" not in rendered


def test_json_body_field_names_are_recorded() -> None:
    assert body_field_names('{"account": "a", "password": "p"}') == ("account", "password")


def test_form_body_field_names_are_recorded() -> None:
    assert body_field_names("login=a&passwd=p&xsrf=t") == ("login", "passwd", "xsrf")


def test_no_value_is_reachable_from_what_is_recorded() -> None:
    """The promise is not that values are redacted; it is that none is returned."""
    names = body_field_names('{"account": "account199", "password": "sup3r-s3cret"}')

    assert names == ("account", "password")
    assert all("sup3r-s3cret" not in name for name in names)
    assert all("account199" not in name for name in names)


def test_a_body_that_cannot_be_parsed_yields_nothing() -> None:
    """Nothing rather than a guess: an invented field name is worse than none."""
    assert body_field_names("<xml><a/></xml>") == ()
    assert body_field_names("") == ()
    assert body_field_names(None) == ()


def test_a_json_array_has_no_field_names() -> None:
    assert body_field_names('["a", "b"]') == ()


def test_a_repeated_field_is_named_once() -> None:
    assert body_field_names("id=1&id=2&name=x") == ("id", "name")


def test_an_observation_carries_the_names_it_was_given() -> None:
    request = ObservedRequest(
        method="POST",
        url="https://h/api/web/login",
        resource_type="xhr",
        carried_body=True,
        body_keys=("account", "password"),
    )

    assert request.body_keys == ("account", "password")
    assert "sup3r" not in repr(request)


def test_a_result_reports_a_visit_that_was_cut_short() -> None:
    """An inventory cut short looks exactly like a small surface."""
    cut = BrowserRunResult(
        final_url="https://h/",
        title="shop",
        status_code=200,
        screenshot=b"",
        blocked_requests=(),
        observed_requests=(observed(),),
        truncated_requests=180,
    )

    assert cut.truncated_requests == 180


def test_a_complete_visit_reports_nothing_truncated() -> None:
    assert result(observed()).truncated_requests == 0


def test_the_ceiling_has_a_default_a_page_will_not_normally_reach() -> None:
    """A heavy application loads a few hundred resources. One storefront visit
    recorded five and a half thousand requests in a minute, which is a loop rather
    than a visit, and nothing bounded it."""
    request = BrowserRunRequest(
        target="https://h/", allowed_hosts=frozenset({"h"}), allowed_ports=frozenset({443})
    )

    assert 100 <= request.maximum_requests <= 1000


def test_page_furniture_is_declined_by_default() -> None:
    """Images and fonts are already dropped from the inventory. Fetching them spends
    the target's rate budget on bytes nothing reads, and on one storefront they were
    almost the whole visit -- leaving reconnaissance no allowance for the probing it
    exists to inform."""
    request = BrowserRunRequest(
        target="https://h/", allowed_hosts=frozenset({"h"}), allowed_ports=frozenset({443})
    )

    assert request.skip_page_furniture is True


def test_scripts_are_never_declined() -> None:
    """The application needs them to run, and reading them is a discovery source."""
    assert "script" not in _NEVER_FETCHED
    assert "xhr" not in _NEVER_FETCHED
    assert "fetch" not in _NEVER_FETCHED
    # Everything declined is already something the inventory discards.
    assert _NEVER_FETCHED <= _NOT_API


def test_a_declined_request_is_not_reported_as_blocked() -> None:
    """Blocked means the page reached outside the engagement, which an operator should
    look at. Declined means we had no use for it, which they should not."""
    outcome = BrowserRunResult(
        final_url="https://h/",
        title="shop",
        status_code=200,
        screenshot=b"",
        blocked_requests=(),
        observed_requests=(observed(),),
        declined_requests=312,
    )

    assert outcome.blocked_requests == ()
    assert outcome.declined_requests == 312


def test_a_visit_has_a_deadline_covering_the_launch() -> None:
    """The per-operation timeout is set on the context, which exists only after the
    browser has launched -- so launching it was unbounded, and so was starting
    Playwright. An agent spent an hour and seven minutes inside one call, having
    authenticated and sent nothing, while its scheduled task reported Running."""
    request = BrowserRunRequest(
        target="https://h/", allowed_hosts=frozenset({"h"}), allowed_ports=frozenset({443})
    )

    assert request.deadline_seconds > (request.timeout_ms + request.settle_ms) / 1000


def test_the_deadline_follows_the_timeouts_it_covers() -> None:
    """Derived rather than configured separately, so raising a timeout cannot leave
    the deadline underneath it."""
    patient = BrowserRunRequest(
        target="https://h/",
        allowed_hosts=frozenset({"h"}),
        allowed_ports=frozenset({443}),
        timeout_ms=45_000,
        settle_ms=8_000,
    )
    brisk = BrowserRunRequest(
        target="https://h/",
        allowed_hosts=frozenset({"h"}),
        allowed_ports=frozenset({443}),
        timeout_ms=5_000,
        settle_ms=1_000,
    )

    assert patient.deadline_seconds > brisk.deadline_seconds


async def test_a_visit_that_never_finishes_is_abandoned() -> None:
    """Timing out is reported as a failed visit, which the caller already treats as a
    lost pass rather than a lost cycle."""

    class Forever(IsolatedBrowserRunner):
        async def _visit(self, request: BrowserRunRequest) -> BrowserRunResult:
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

    class Impatient(Forever):
        pass

    request = BrowserRunRequest(
        target="https://h/",
        allowed_hosts=frozenset({"h"}),
        allowed_ports=frozenset({443}),
        timeout_ms=1_000,
        settle_ms=1_000,
    )
    # The allowance for launching a browser dominates the derived deadline, which is
    # right in production and far too patient for a test, so it is overridden here.
    with (
        mock.patch.object(
            type(request), "deadline_seconds", property(lambda _self: 0.05)
        ),
        pytest.raises(BrowserVisitTimeoutError, match="exceeded"),
    ):
        await Impatient().run(request)
