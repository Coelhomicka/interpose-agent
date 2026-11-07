"""Attacks the broker must refuse even when the destination host is allowed."""

from __future__ import annotations

import gzip

import httpx
import pytest
from fastapi.testclient import TestClient

from interpose.core.policies import PolicyDocument
from interpose.core.redaction import SecretRedactionEngine
from interpose.proxy.http_proxy import create_proxy_app

BROKER_URL = "http://127.0.0.1:9876"
SECRET_VALUE = "ghp_real_secret_value"


class _Upstream:
    """Stands in for httpx.AsyncClient and records what would have been sent."""

    def __init__(self, response: httpx.Response | None = None) -> None:
        self.calls: list[dict] = []
        self.response = response

    def install(self, monkeypatch) -> None:
        upstream = self

        class FakeAsyncClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc_info):
                return None

            async def request(self, method, url, **kwargs):
                upstream.calls.append({"method": method, "url": url, **kwargs})
                return upstream.response or httpx.Response(200, json={}, request=httpx.Request(method, url))

        monkeypatch.setattr("interpose.proxy.http_proxy.httpx.AsyncClient", FakeAsyncClient)


def _store(container, policy_yaml: str) -> None:
    container.secret_store.store("secret://github/prod", SECRET_VALUE)
    container.policy_repository.store(PolicyDocument.from_yaml(policy_yaml))


def _forbid_resolution(container, monkeypatch) -> None:
    def fail(reference):
        raise AssertionError(f"secret resolved for a request that must be denied: {reference}")

    monkeypatch.setattr(container.secret_store, "resolve", fail)


GITHUB_POLICY = """
secret: github/prod
allow:
  hosts:
    - api.github.com
"""


@pytest.fixture()
def client(runtime_container):
    return TestClient(create_proxy_app(runtime_container), base_url=BROKER_URL)


def test_reference_in_body_is_denied_even_for_allowed_host(runtime_container, client, monkeypatch):
    # The classic exfiltration: publish the token through the very API it unlocks.
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)
    upstream = _Upstream()
    upstream.install(monkeypatch)

    response = client.post(
        "/proxy/api.github.com/gists",
        headers={"Authorization": "Bearer secret://github/prod"},
        json={"public": True, "files": {"a.txt": {"content": "secret://github/prod"}}},
    )

    assert response.status_code == 403
    assert "body" in response.text
    assert upstream.calls == []


def test_reference_in_plain_text_body_is_denied(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.post(
        "/proxy/api.github.com/markdown/raw",
        headers={"Content-Type": "text/plain"},
        content="echo secret://github/prod",
    )

    assert response.status_code == 403


def test_reference_in_undeclared_header_is_denied(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.get(
        "/proxy/api.github.com/user",
        headers={"X-Echo-Me": "secret://github/prod"},
    )

    assert response.status_code == 403
    assert "x-echo-me" in response.text.lower()


def test_reference_as_query_key_is_denied(runtime_container, client, monkeypatch):
    _store(
        runtime_container,
        GITHUB_POLICY + "inject:\n  - query: key\n",
    )
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.get("/proxy/api.github.com/search?secret://github/prod=1")

    assert response.status_code == 403


def test_query_slot_must_be_declared(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.get("/proxy/api.github.com/search", params={"key": "secret://github/prod"})

    assert response.status_code == 403


def test_declared_query_slot_is_substituted(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY + "inject:\n  - query: key\n")
    upstream = _Upstream()
    upstream.install(monkeypatch)

    response = client.get("/proxy/api.github.com/search", params={"key": "secret://github/prod"})

    assert response.status_code == 200
    assert upstream.calls[0]["url"] == f"https://api.github.com/search?key={SECRET_VALUE}"


def test_declared_inject_list_replaces_default_headers(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY + "inject:\n  - query: key\n")
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.get(
        "/proxy/api.github.com/user",
        headers={"Authorization": "Bearer secret://github/prod"},
    )

    assert response.status_code == 403


def test_path_outside_allow_list_is_denied(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY + "paths:\n  - /user\n  - /repos/*\n")
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.post(
        "/proxy/api.github.com/gists",
        headers={"Authorization": "Bearer secret://github/prod"},
    )

    assert response.status_code == 403
    assert "path /gists" in response.text


def test_path_inside_allow_list_is_allowed(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY + "paths:\n  - /user\n  - /repos/*\n")
    upstream = _Upstream()
    upstream.install(monkeypatch)

    response = client.get(
        "/proxy/api.github.com/repos/octo/hello",
        headers={"Authorization": "Bearer secret://github/prod"},
    )

    assert response.status_code == 200
    assert upstream.calls[0]["headers"]["authorization"] == f"Bearer {SECRET_VALUE}"


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
def test_browser_originated_requests_are_rejected(runtime_container, client, monkeypatch, headers):
    # A web page can send form or text/plain POSTs to 127.0.0.1 without a preflight.
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)

    response = client.get(
        "/proxy/api.github.com/user",
        headers={"Authorization": "Bearer secret://github/prod", **headers},
    )

    assert response.status_code == 403


def test_dns_rebinding_host_is_rejected(runtime_container, monkeypatch):
    _store(runtime_container, GITHUB_POLICY)
    _forbid_resolution(runtime_container, monkeypatch)
    rebinding_client = TestClient(create_proxy_app(runtime_container), base_url="http://rebind.evil.example:9876")

    response = rebinding_client.get(
        "/proxy/api.github.com/user",
        headers={"Authorization": "Bearer secret://github/prod"},
    )

    assert response.status_code == 403
    assert "Host" in response.text


def test_content_encoding_is_not_forwarded_after_decoding(runtime_container, client, monkeypatch):
    _store(runtime_container, GITHUB_POLICY)
    upstream = _Upstream(
        httpx.Response(
            200,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
            content=gzip.compress(b'{"ok": true}'),
            request=httpx.Request("GET", "https://api.github.com/user"),
        )
    )
    upstream.install(monkeypatch)

    response = client.get(
        "/proxy/api.github.com/user",
        headers={"Authorization": "Bearer secret://github/prod"},
    )

    assert "content-encoding" not in {key.lower() for key in response.headers}
    assert response.json() == {"ok": True}


def test_binary_redaction_survives_invalid_utf8():
    engine = SecretRedactionEngine()
    engine.register(SECRET_VALUE)

    payload = b"\xff\xfe" + SECRET_VALUE.encode() + b"\x80"

    assert engine.redact_bytes(payload) == b"\xff\xfe[REDACTED]\x80"
