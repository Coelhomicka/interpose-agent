from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from interpose.core.policies import PolicyDocument
from interpose.proxy.http_proxy import create_proxy_app, parse_local_transport_target, parse_proxy_target

BROKER_URL = "http://127.0.0.1:9876"


def _client(container):
    return TestClient(create_proxy_app(container), base_url=BROKER_URL)


def test_local_transport_defaults_external_destination_to_https():
    target = parse_local_transport_target(
        "proxy/api.openai.com/v1/responses",
        "api_key=secret://openai/prod",
    )

    assert target is not None
    assert target.scheme == "https"
    assert target.host == "api.openai.com"
    assert target.path == "/v1/responses"


def test_local_transport_uses_http_only_for_loopback():
    target = parse_local_transport_target("proxy/localhost:8001/health", "")

    assert target is not None
    assert target.scheme == "http"
    assert target.host == "localhost:8001"
    assert target.path == "/health"


def test_forward_proxy_parses_absolute_http_target():
    target = parse_proxy_target(
        raw_target="http://localhost:8001/health?secret=secret://apichave/teste",
        host_header="localhost:8001",
        fallback_scheme="https",
        fallback_path="ignored",
        fallback_query="secret=secret://apichave/teste",
    )

    assert target.scheme == "http"
    assert target.host == "localhost:8001"
    assert target.path == "/health"
    assert target.query == "secret=secret://apichave/teste"


def test_forward_proxy_preserves_encoded_reference_query_for_decoding():
    target = parse_proxy_target(
        raw_target="http://localhost:8001/health?secret=secret%3A%2F%2Fapichave%2Fteste",
        host_header="localhost:8001",
        fallback_scheme="https",
        fallback_path="ignored",
        fallback_query="secret=secret%3A%2F%2Fapichave%2Fteste",
    )

    assert target.query == "secret=secret%3A%2F%2Fapichave%2Fteste"


def test_proxy_rejects_absolute_target_credentials():
    with pytest.raises(ValueError, match="invalid absolute proxy target"):
        parse_proxy_target(
            raw_target="http://user:password@localhost:8001/health",
            host_header=None,
            fallback_scheme="http",
            fallback_path="health",
            fallback_query="",
        )


def test_local_transport_resolves_after_policy_and_redacts_response(runtime_container, monkeypatch):
    runtime_container.secret_store.store("secret://service/prod", "real-secret-value")
    runtime_container.policy_repository.store(
        PolicyDocument.from_yaml(
            """
secret: service/prod
allow:
  hosts:
    - api.example.com
methods:
  - POST
schemes:
  - https
"""
        )
    )
    captured = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            captured["client_options"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

        async def request(self, method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return httpx.Response(
                200,
                json={"echo": "real-secret-value"},
                request=httpx.Request(method, url),
            )

    monkeypatch.setattr("interpose.proxy.http_proxy.httpx.AsyncClient", FakeAsyncClient)
    client = _client(runtime_container)

    response = client.post(
        "/proxy/api.example.com/v1/resource",
        headers={"Authorization": "Bearer secret://service/prod"},
        json={"input": "hello"},
    )

    assert response.status_code == 200
    assert response.json() == {"echo": "[REDACTED]"}
    assert captured["url"] == "https://api.example.com/v1/resource"
    assert captured["headers"]["authorization"] == "Bearer real-secret-value"
    assert captured["json"] == {"input": "hello"}
    assert captured["client_options"]["trust_env"] is False


def test_local_transport_denies_wrong_host_before_resolution(runtime_container, monkeypatch):
    runtime_container.secret_store.store("secret://service/prod", "real-secret-value")
    runtime_container.policy_repository.store(
        PolicyDocument.from_yaml(
            """
secret: service/prod
allow:
  hosts:
    - api.example.com
"""
        )
    )

    def fail_if_resolved(reference):
        raise AssertionError(f"secret resolved before policy decision: {reference}")

    monkeypatch.setattr(runtime_container.secret_store, "resolve", fail_if_resolved)
    client = _client(runtime_container)

    response = client.get(
        "/proxy/evil.example/collect",
        headers={"Authorization": "Bearer secret://service/prod"},
    )

    assert response.status_code == 403
    assert "PolicyViolation" in response.text
