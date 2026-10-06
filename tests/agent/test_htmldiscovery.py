"""Tests for recovering a server-rendered application's surface from its HTML."""

from __future__ import annotations

import pytest

from vuln_proof_claw.agent.htmldiscovery import extract_endpoints, inventory

PAGE = "https://10.26.0.31:8088/admin/dashboard.php"


def paths(html: str, *, page_url: str = PAGE) -> list[tuple[str, str]]:
    return list(inventory(extract_endpoints(html, page_url=page_url)))


def test_a_form_contributes_its_declared_method() -> None:
    html = '<form method="POST" action="/index.php"></form><form action="/search.php"></form>'

    assert paths(html) == [("POST", "/index.php"), ("GET", "/search.php")]


def test_a_form_without_an_action_posts_back_to_its_own_page() -> None:
    html = '<form method="post"></form>'

    assert paths(html) == [("POST", "/admin/dashboard.php")]


def test_a_relative_action_resolves_against_the_page_not_the_root() -> None:
    """index.php on /admin/ is /admin/index.php; the root is a different endpoint."""
    html = '<form method="POST" action="index.php"></form>'

    assert paths(html) == [("POST", "/admin/index.php")]


def test_links_become_reads() -> None:
    html = '<a href="/users.php?id=3">u</a><a href="reports.php">r</a>'

    assert paths(html) == [("GET", "/users.php?id=3"), ("GET", "/admin/reports.php")]


@pytest.mark.parametrize(
    "href",
    ["javascript:void(0)", "mailto:a@b.c", "tel:+886", "#section", "data:text/html,x", ""],
)
def test_a_reference_that_makes_no_request_is_skipped(href: str) -> None:
    assert paths(f'<a href="{href}">x</a>') == []


def test_another_site_is_not_this_application_surface() -> None:
    html = '<a href="https://example.com/x">out</a><a href="//cdn.test/y">proto</a>'

    assert paths(html) == []


def test_the_same_request_is_only_listed_once() -> None:
    html = '<a href="/a.php">1</a><a href="/a.php">2</a><a href="/a.php?x=1">3</a>'

    assert paths(html) == [("GET", "/a.php"), ("GET", "/a.php?x=1")]


def test_a_form_and_a_link_to_one_path_are_different_requests() -> None:
    """POST /x and GET /x can behave completely differently; both are worth listing."""
    html = '<form method="POST" action="/x.php"></form><a href="/x.php">x</a>'

    assert paths(html) == [("POST", "/x.php"), ("GET", "/x.php")]


def test_an_unrecognised_method_is_not_assumed_to_write() -> None:
    """Treating an odd value as POST would invent a state change that is not there."""
    html = '<form method="DELETE" action="/x.php"></form>'

    assert paths(html) == [("GET", "/x.php")]


def test_the_origin_of_each_endpoint_is_recorded() -> None:
    found = extract_endpoints(
        '<form method="POST" action="/save.php"></form><a href="/list.php">l</a>',
        page_url=PAGE,
    )

    assert [item.origin for item in found] == ["form", "link"]


def test_an_empty_page_yields_nothing() -> None:
    assert paths("<html><body><p>hello</p></body></html>") == []


def test_the_real_shape_of_the_it01_login_page() -> None:
    """Observed: IT-01's entry page is a single PHP form, not an API client."""
    html = (
        '<form name="loginform" method="POST" action="index.php">'
        '<input name="ulogin"><input type="password" name="upasswd">'
        "</form>"
    )

    assert paths(html, page_url="https://10.26.0.30/") == [("POST", "/index.php")]
