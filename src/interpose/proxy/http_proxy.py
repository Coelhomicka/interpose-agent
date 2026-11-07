from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from ..container import RuntimeContainer, create_container
from ..core.local_guard import browser_request_rejection, is_loopback_authority
from ..core.policies import PolicyEngine, RequestLocation
from ..core.references import SecretReference, collect_secret_references
from ..core.scopes import ScopeContext
from ..core.substitution import SecretSubstitutionEngine
from ..models import DestinationContext
from ..secrets.base import SecretNotFound
from ..secrets.encrypted_local import ScopedSecretStore

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "x-interpose-scheme",
}


# httpx decodes the upstream body, so the encoding header no longer describes what
# the client receives; forwarding it makes the client try to decompress plain bytes.
_RESPONSE_ONLY_DROPPED_HEADERS = {"content-encoding", "server", "date"}
# ``server`` and ``date`` are re-added by the broker's own HTTP server; forwarding
# the upstream copies as well produced duplicates and fingerprinted the upstream.

# ``/p/<project-id>/proxy/...`` resolves secrets and policies in that project's
# scope, then global. Plain ``/proxy/...`` uses the broker's own scope. A long-lived
# broker (the OS service) serves every project, so the project travels in the URL.
_PROJECT_PREFIX_RE = re.compile(r"^p/([a-z0-9][a-z0-9-]{0,62})/(proxy/.*)$", re.DOTALL)

def _filtered_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in _HOP_BY_HOP_HEADERS
    }


def _response_headers(headers: httpx.Headers, redactor) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _HOP_BY_HOP_HEADERS or key.lower() in _RESPONSE_ONLY_DROPPED_HEADERS:
            continue
        result[key] = redactor.redact(value)
    return result


@dataclass(frozen=True)
class ProxyTarget:
    scheme: str
    host: str
    path: str
    query: str


def parse_proxy_target(
    *,
    raw_target: str,
    host_header: str | None,
    fallback_scheme: str,
    fallback_path: str,
    fallback_query: str,
) -> ProxyTarget:
    if raw_target.startswith(("http://", "https://")):
        parsed = urlsplit(raw_target)
        if parsed.username or parsed.password or not parsed.hostname:
            raise ValueError("invalid absolute proxy target")
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return ProxyTarget(
            scheme=parsed.scheme,
            host=host,
            path=parsed.path or "/",
            query=parsed.query or fallback_query,
        )

    if not host_header:
        raise ValueError("missing Host header")
    scheme = fallback_scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("invalid upstream scheme")
    return ProxyTarget(
        scheme=scheme,
        host=host_header,
        path=f"/{fallback_path.lstrip('/')}",
        query=fallback_query,
    )


def _normalized_authority(value: str) -> str:
    try:
        parsed = urlsplit(f"//{value}")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid local transport destination") from exc
    if parsed.username or parsed.password or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("invalid local transport destination")
    hostname = parsed.hostname.lower()
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{rendered_host}:{port}" if port else rendered_host


def parse_local_transport_target(path: str, query: str) -> ProxyTarget | None:
    if not path.startswith("proxy/"):
        return None
    destination_and_path = path[len("proxy/"):]
    destination, separator, upstream_path = destination_and_path.partition("/")
    if not destination:
        raise ValueError("local transport destination is required")
    authority = _normalized_authority(destination)
    scheme = "http" if is_loopback_authority(authority) else "https"
    return ProxyTarget(
        scheme=scheme,
        host=authority,
        path=f"/{upstream_path}" if separator else "/",
        query=query,
    )


def _located_references(
    headers: dict[str, str],
    query_pairs: list[tuple[str, str]],
    body: Any,
    *,
    form_body: bool,
) -> list[tuple[SecretReference, RequestLocation]]:
    """Every reference in the request, paired with where it was found.

    Field *names* never match an injection slot, so a reference used as a header
    name or a query key is reported under a kind no policy can grant.
    """
    found: list[tuple[SecretReference, RequestLocation]] = []
    seen: set[tuple[str, RequestLocation]] = set()

    def add(value: Any, location: RequestLocation) -> None:
        for reference in collect_secret_references(value):
            key = (reference.canonical, location)
            if key not in seen:
                seen.add(key)
                found.append((reference, location))

    for name, value in headers.items():
        add(name, RequestLocation(kind="header-name"))
        add(value, RequestLocation(kind="header", name=name))
    for name, value in query_pairs:
        add(name, RequestLocation(kind="query-name"))
        add(value, RequestLocation(kind="query", name=name))
    if form_body and isinstance(body, list):
        for name, value in body:
            add(name, RequestLocation(kind="form-name"))
            add(value, RequestLocation(kind="form", name=name))
    else:
        add(body, RequestLocation(kind="body"))
    return found


def create_proxy_app(container: RuntimeContainer | None = None) -> FastAPI:
    runtime = container or create_container()
    app = FastAPI(title="Interpose Proxy", version="0.1.0")

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"],
    )
    async def proxy(path: str, request: Request) -> Response:
        started = time.perf_counter()
        if request.method == "CONNECT":
            return Response(
                content=(
                    "HTTPS CONNECT is not supported; "
                    "use an explicit broker until trusted TLS termination is configured"
                ),
                status_code=501,
            )

        rejection = browser_request_rejection(dict(request.headers.items()))
        if rejection is not None:
            return Response(content=f"Forbidden: {rejection}", status_code=403)

        policy_engine = runtime.policy_engine
        secret_store = runtime.secret_store
        project_match = _PROJECT_PREFIX_RE.match(path)
        if project_match:
            project_id, path = project_match.group(1), project_match.group(2)
            if runtime.project_registry.get(project_id) is None:
                return Response(content=f"unknown project: {project_id}", status_code=404)
            project_context = ScopeContext(project_id=project_id)
            policy_engine = PolicyEngine(runtime.policy_repository, project_context)
            secret_store = ScopedSecretStore(runtime.secret_store.backend, project_context)

        try:
            target = parse_local_transport_target(path, request.url.query)
            if target is not None and not is_loopback_authority(request.headers.get("host", "")):
                # The local transport is addressed by path, so the Host header must be
                # the broker itself. Anything else is a DNS-rebinding page that resolved
                # its own name to 127.0.0.1 to read responses as same-origin.
                return Response(content="Forbidden: Host must be the loopback broker", status_code=403)
            if target is None:
                raw_path = request.scope.get("raw_path", b"")
                raw_target = (
                    raw_path.decode("ascii", errors="replace")
                    if isinstance(raw_path, bytes)
                    else str(raw_path)
                )
                scope_path = str(request.scope.get("path", ""))
                if not raw_target.startswith(("http://", "https://")) and scope_path.startswith(("http://", "https://")):
                    raw_target = scope_path
                target = parse_proxy_target(
                    raw_target=raw_target,
                    host_header=request.headers.get("host"),
                    fallback_scheme=request.headers.get(
                        "x-interpose-scheme",
                        str(request.scope.get("scheme", "http")),
                    ),
                    fallback_path=path,
                    fallback_query=request.url.query,
                )
        except ValueError as exc:
            return Response(content=str(exc), status_code=400)

        raw_body = await request.body()
        body_text = raw_body.decode("utf-8", errors="replace") if raw_body else ""
        content_type = request.headers.get("content-type", "")
        header_values = dict(request.headers.items())
        outbound_headers = _filtered_headers(header_values)
        query_text = target.query
        query_pairs = parse_qsl(query_text, keep_blank_values=True) if query_text else []
        body_for_discovery: Any = body_text
        if raw_body and "application/json" in content_type:
            try:
                body_for_discovery = json.loads(body_text)
            except json.JSONDecodeError:
                body_for_discovery = body_text
        elif raw_body and "application/x-www-form-urlencoded" in content_type:
            body_for_discovery = parse_qsl(body_text, keep_blank_values=True)
        payload_for_discovery = {
            "headers": outbound_headers,
            "body": body_for_discovery,
            "query": query_pairs,
        }
        references = collect_secret_references(payload_for_discovery)
        located = _located_references(
            outbound_headers,
            query_pairs,
            body_for_discovery,
            form_body=bool(raw_body) and "application/x-www-form-urlencoded" in content_type,
        )
        destination = DestinationContext(
            host=target.host,
            method=request.method,
            scheme=target.scheme,
            url=f"{target.scheme}://{target.host}{target.path}",
            path=target.path,
        )

        for reference, location in located:
            decision = policy_engine.evaluate(reference, destination, location=location)
            if not decision.allowed:
                runtime.audit_logger.record(
                    session="proxy",
                    agent=runtime.config.agent_name,
                    secret_reference=reference.canonical,
                    destination=target.host,
                    action=f"HTTP_{request.method}",
                    policy_result="deny",
                    status="blocked",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    details={"reason": decision.reason, "location": location.describe()},
                )
                return Response(content=f"PolicyViolation: {decision.reason}", status_code=403)

        substitution = SecretSubstitutionEngine(secret_store.resolve)

        try:
            resolved_headers = outbound_headers
            if resolved_headers:
                resolved_headers = substitution.substitute(resolved_headers).value

            resolved_query_pairs = substitution.substitute(query_pairs).value if query_pairs else []
            resolved_query = urlencode(resolved_query_pairs) if resolved_query_pairs else ""
            upstream_url = f"{target.scheme}://{target.host}{target.path}"
            if resolved_query:
                upstream_url = f"{upstream_url}?{resolved_query}"

            request_content: Any = None
            request_json: Any = None
            if raw_body:
                if "application/json" in content_type:
                    if isinstance(body_for_discovery, (dict, list)):
                        request_json = substitution.substitute(body_for_discovery).value
                    else:
                        request_content = substitution.substitute(body_text).value.encode("utf-8")
                elif "application/x-www-form-urlencoded" in content_type:
                    resolved_form = substitution.substitute(body_for_discovery).value
                    request_content = urlencode(resolved_form).encode("utf-8")
                else:
                    request_content = substitution.substitute(body_text).value.encode("utf-8")

            resolved_values = [
                resolution.value
                for resolution in substitution.substitute(payload_for_discovery).resolutions
            ]
            runtime.redaction_engine.register_many(resolved_values)
        except SecretNotFound as exc:
            runtime.audit_logger.record(
                session="proxy",
                agent=runtime.config.agent_name,
                secret_reference=",".join(reference.canonical for reference in references) or "none",
                destination=target.host,
                action=f"HTTP_{request.method}",
                policy_result="deny",
                status="missing-secret",
                duration_ms=int((time.perf_counter() - started) * 1000),
                details={"reason": str(exc)},
            )
            return Response(content="SecretNotFound", status_code=404)

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=False, trust_env=False) as client:
                upstream_response = await client.request(
                    request.method,
                    upstream_url,
                    headers=resolved_headers,
                    content=request_content,
                    json=request_json,
                )
        except Exception as exc:
            return Response(content=runtime.redaction_engine.redact(str(exc)), status_code=502)

        response_headers = _response_headers(upstream_response.headers, runtime.redaction_engine)
        content = upstream_response.content
        text_mode = False
        upstream_content_type = upstream_response.headers.get("content-type", "")
        if upstream_content_type.startswith(("text/", "application/json", "application/xml")):
            try:
                content = runtime.redaction_engine.redact(upstream_response.text).encode("utf-8")
                text_mode = True
            except Exception:
                content = upstream_response.content
        else:
            content = runtime.redaction_engine.redact_bytes(content)

        runtime.audit_logger.record(
            session="proxy",
            agent=runtime.config.agent_name,
            secret_reference=",".join(reference.canonical for reference in references) or "none",
            destination=target.host,
            action=f"HTTP_{request.method}",
            policy_result="allow",
            status=str(upstream_response.status_code),
            duration_ms=int((time.perf_counter() - started) * 1000),
            details={
                "upstream_url": f"{target.scheme}://{target.host}{target.path}",
                "query_parameter_count": len(query_pairs),
                "text_mode": text_mode,
            },
        )
        return Response(
            content=content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app
