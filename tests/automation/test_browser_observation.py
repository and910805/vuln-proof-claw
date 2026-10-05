"""Tests for recovering a surface by watching what an application actually requests.

Parsing a bundle only finds the idioms the parser knows. A recorded request has no
idiom, which is the whole reason this path exists — so what matters here is that the
recording is faithful, bounded, and safe to put in evidence.
"""

from __future__ import annotations

import pytest

from vuln_proof_claw.automation.browser import (
    BrowserRunResult,
    ObservedRequest,
    inventory,
)


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
