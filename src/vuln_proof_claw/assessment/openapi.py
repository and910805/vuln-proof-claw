"""Bounded semantic inventory for captured OpenAPI and Swagger documents."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

from vuln_proof_claw.execution.http_capture import HttpCaptureResponse
from vuln_proof_claw.policy.scope import normalize_target

_HTTP_METHODS = ("get", "head", "post", "put", "patch", "delete", "options", "trace")
_READ_METHODS = frozenset({"get", "head"})
_MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_MAX_OPERATIONS = 500


@dataclass(frozen=True, slots=True)
class ApiOperation:
    """One normalized OpenAPI operation and its safe-probe eligibility."""

    method: str
    path: str
    target: str
    operation_id: str | None
    requires_authentication: bool
    required_parameters: tuple[str, ...]

    @property
    def safe_to_probe(self) -> bool:
        return (
            self.method.lower() in _READ_METHODS
            and not self.required_parameters
            and "{" not in self.path
        )


@dataclass(frozen=True, slots=True)
class OpenApiDocument:
    """A conservative inventory extracted from one captured API description."""

    source_url: str
    title: str
    specification: str
    operations: tuple[ApiOperation, ...]
    truncated: bool = False


def parse_openapi_document(
    source_url: str,
    response: HttpCaptureResponse,
) -> OpenApiDocument | None:
    """Parse a bounded JSON OpenAPI/Swagger document without resolving external refs."""
    if not response.body or len(response.body) > _MAX_DOCUMENT_BYTES:
        return None
    try:
        payload = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    openapi = payload.get("openapi")
    swagger = payload.get("swagger")
    if not isinstance(openapi, str) and swagger != "2.0":
        return None
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return None

    normalized_source = str(normalize_target(source_url))
    base_url = _base_url(normalized_source, payload)
    root_security = payload.get("security")
    info = payload.get("info")
    title_value = info.get("title") if isinstance(info, dict) else None
    title = title_value.strip() if isinstance(title_value, str) and title_value.strip() else "API"
    operations: list[ApiOperation] = []
    truncated = False
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            continue
        path_parameters = _required_parameters(path_item.get("parameters"))
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            if len(operations) >= _MAX_OPERATIONS:
                truncated = True
                break
            operation_parameters = _required_parameters(operation.get("parameters"))
            required = tuple(dict.fromkeys((*path_parameters, *operation_parameters)))
            security = operation.get("security", root_security)
            operation_id = operation.get("operationId")
            operations.append(
                ApiOperation(
                    method=method.upper(),
                    path=path,
                    target=str(normalize_target(_join_operation(base_url, path))),
                    operation_id=(
                        operation_id.strip()
                        if isinstance(operation_id, str) and operation_id.strip()
                        else None
                    ),
                    requires_authentication=bool(security),
                    required_parameters=required,
                )
            )
        if truncated:
            break
    specification = f"OpenAPI {openapi}" if isinstance(openapi, str) else "Swagger 2.0"
    return OpenApiDocument(
        source_url=normalized_source,
        title=title,
        specification=specification,
        operations=tuple(operations),
        truncated=truncated,
    )


def _required_parameters(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        if not isinstance(item, dict) or not item.get("required"):
            continue
        name = item.get("name")
        location = item.get("in")
        if isinstance(name, str):
            result.append(f"{location}:{name}" if isinstance(location, str) else name)
    return tuple(result)


def _base_url(source_url: str, payload: dict[str, object]) -> str:
    servers = payload.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server = servers[0].get("url")
        if isinstance(server, str) and server.strip() and "{" not in server:
            return urljoin(source_url, server.strip())
    split = urlsplit(source_url)
    scheme = split.scheme
    schemes = payload.get("schemes")
    if isinstance(schemes, list) and schemes and isinstance(schemes[0], str):
        scheme = schemes[0]
    host = payload.get("host")
    netloc = host if isinstance(host, str) and host else split.netloc
    base_path = payload.get("basePath")
    path = base_path if isinstance(base_path, str) else "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _join_operation(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"
