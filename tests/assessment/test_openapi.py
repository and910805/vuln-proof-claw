"""Semantic OpenAPI inventory tests."""

import json

from vuln_proof_claw.assessment.openapi import parse_openapi_document
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse


def response(payload: object) -> HttpCaptureResponse:
    return HttpCaptureResponse(
        status_code=200,
        final_target="https://api.example.test/openapi.json",
        headers=(("content-type", "application/json"),),
        body=json.dumps(payload).encode(),
        duration_ms=1,
    )


def test_openapi_inventory_marks_only_parameterless_reads_safe() -> None:
    document = parse_openapi_document(
        "https://api.example.test/openapi.json",
        response(
            {
                "openapi": "3.1.0",
                "info": {"title": "Example"},
                "servers": [{"url": "/v1"}],
                "security": [{"bearer": []}],
                "paths": {
                    "/health": {"get": {"operationId": "health", "security": []}},
                    "/users/{id}": {
                        "get": {
                            "parameters": [
                                {"name": "id", "in": "path", "required": True}
                            ]
                        }
                    },
                    "/users": {"post": {"operationId": "createUser"}},
                },
            }
        ),
    )

    assert document is not None
    assert document.title == "Example"
    assert document.specification == "OpenAPI 3.1.0"
    assert [(item.method, item.target) for item in document.operations] == [
        ("GET", "https://api.example.test:443/v1/health"),
        ("GET", "https://api.example.test:443/v1/users/{id}"),
        ("POST", "https://api.example.test:443/v1/users"),
    ]
    assert document.operations[0].safe_to_probe is True
    assert document.operations[0].requires_authentication is False
    assert document.operations[1].safe_to_probe is False
    assert document.operations[2].safe_to_probe is False
    assert document.operations[2].requires_authentication is True


def test_non_openapi_json_is_ignored() -> None:
    assert (
        parse_openapi_document(
            "https://api.example.test/data.json",
            response({"items": []}),
        )
        is None
    )
