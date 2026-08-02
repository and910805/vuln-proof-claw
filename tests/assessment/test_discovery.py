"""Coverage for deterministic same-origin Web discovery."""

from vuln_proof_claw.assessment.discovery import DISCOVERY_PRESETS, discover_targets
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse


def response(body: bytes, content_type: str = "text/html") -> HttpCaptureResponse:
    return HttpCaptureResponse(
        status_code=200,
        final_target="https://example.test:443/start",
        headers=(("Content-Type", content_type),),
        body=body,
        duration_ms=1,
    )


def test_discovers_unique_same_origin_html_references() -> None:
    result = discover_targets(
        "https://example.test/start",
        response(
            b'<a href="/account?tab=1#top">Account</a>'
            b'<script src="/assets/app.js"></script>'
            b'<form action="/login"></form>'
            b'<a href="https://outside.test/escape">Outside</a>'
            b'<a href="javascript:alert(1)">No</a>'
        ),
    )

    assert [(item.url, item.kind) for item in result] == [
        ("https://example.test:443/account", "link"),
        ("https://example.test:443/assets/app.js", "asset"),
        ("https://example.test:443/login", "form"),
    ]


def test_discovers_sitemaps_javascript_and_conventional_targets() -> None:
    sitemap = discover_targets(
        "https://example.test/start",
        response(
            b"<urlset><url><loc>https://example.test/docs</loc></url></urlset>",
            "application/xml",
        ),
    )
    javascript = discover_targets(
        "https://example.test/start",
        response(b'const api = "/api/v2/users.json";', "application/javascript"),
    )
    conventional = discover_targets(
        "https://example.test/start",
        response(b"<title>Home</title>"),
        include_conventional=True,
    )

    assert sitemap[0].url == "https://example.test:443/docs"
    assert javascript[0].url == "https://example.test:443/api/v2/users.json"
    assert {item.url for item in conventional} >= {
        "https://example.test:443/robots.txt",
        "https://example.test:443/.well-known/security.txt",
        "https://example.test:443/openapi.json",
    }


def test_discovery_is_bounded_and_presets_are_hard_limited() -> None:
    links = b"".join(f'<a href="/{index}"></a>'.encode() for index in range(10))
    result = discover_targets("https://example.test/start", response(links), max_targets=3)

    assert len(result) == 3
    assert DISCOVERY_PRESETS["safe"].request_budget == 5
    assert DISCOVERY_PRESETS["deep"].request_budget == 30
