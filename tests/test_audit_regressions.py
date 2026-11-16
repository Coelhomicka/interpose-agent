# ruff: noqa: RUF001  (confusable Unicode characters are the point of these tests)
"""Regression tests for the findings of the November 2026 adversarial audit.

Each test reproduces an attack against the broker with a fake upstream and asserts
it is refused. See docs/en/SECURITY_AUDIT.md.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from interpose.core.policies import PolicyDocument, PolicyError, host_matches
from interpose.core.redaction import SecretRedactionEngine
from interpose.proxy.http_proxy import (
    ProxyTarget,
    _normalized_authority,
    create_proxy_app,
    verified_upstream_url,
)

BROKER_URL = "http://127.0.0.1:9876"
SECRET_VALUE = "ghp_real_secret_value"

WILDCARD_POLICY = """
secret: github/prod
allow:
  hosts:
    - "*.example.com"
"""


class _Upstream:
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
                upstream.calls.append({"method": method, "url": httpx.URL(url), **kwargs})
                return upstream.response or httpx.Response(200, json={}, request=httpx.Request(method, url))

        monkeypatch.setattr("interpose.proxy.http_proxy.httpx.AsyncClient", FakeAsyncClient)


def _store(container, policy_yaml: str) -> None:
    container.secret_store.store("secret://github/prod", SECRET_VALUE)
    container.policy_repository.store(PolicyDocument.from_yaml(policy_yaml))


@pytest.fixture()
def client(runtime_container):
    return TestClient(create_proxy_app(runtime_container), base_url=BROKER_URL)


# --- Finding 1: policy host vs connection host --------------------------------


@pytest.mark.parametrize(
    "host_header",
    [
        "attacker.test#.example.com",
        "attacker.test/.example.com",
        "attacker.test?.example.com",
        "attacker.test@a.example.com",
        "attacker.test\\.example.com",
        "attacker.test%23.example.com",
        "xn--attacker.test:443#.example.com",
        "a.example.com:443@attacker.test",
    ],
)
def test_host_header_cannot_smuggle_a_different_authority(runtime_container, client, monkeypatch, host_header):
    _store(runtime_container, WILDCARD_POLICY)
    upstream = _Upstream()
    upstream.install(monkeypatch)

    try:
        response = client.get(
            "/user",
            headers={
                "Host": host_header,
                "X-Interpose-Scheme": "https",
                "Authorization": "Bearer secret://github/prod",
            },
        )
    except (httpx.InvalidURL, httpx.LocalProtocolError, ValueError):
        return  # the test client itself refused to send it; nothing reached the broker

    assert response.status_code in {400, 403}
    assert upstream.calls == []


def test_host_header_mode_still_works_for_a_clean_host(runtime_container, client, monkeypatch):
    _store(runtime_container, WILDCARD_POLICY)
    upstream = _Upstream()
    upstream.install(monkeypatch)

    response = client.get(
        "/user",
        headers={"Host": "api.example.com", "X-Interpose-Scheme": "https", "Authorization": "Bearer secret://github/prod"},
    )

    assert response.status_code == 200
    assert upstream.calls[0]["url"].host == "api.example.com"


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("api.example.com", "*.example.com", True),
        ("a.b.example.com", "*.example.com", True),
        ("example.com", "*.example.com", False),
        ("evilexample.com", "*.example.com", False),
        ("example.com.evil.test", "*.example.com", False),
        ("api.example.com", "api.example.com", True),
        ("api.example.com:8443", "api.example.com", False),
        ("localhost:8001", "localhost:8001", True),
        ("anything.test", "*", True),
        ("api.evil.test", "api.*", False),
        ("evilexample.com", "*example.com", False),
    ],
)
def test_allow_patterns_are_label_aware(host, pattern, expected):
    assert host_matches(host, pattern) is expected


@pytest.mark.parametrize("pattern", ["api.*", "*example.com", "api.*.com", "a*b.example.com"])
def test_glob_allow_patterns_are_refused_when_written(pattern):
    with pytest.raises(PolicyError):
        PolicyDocument.from_yaml(f"secret: github/prod\nallow:\n  hosts:\n    - '{pattern}'\n")


@pytest.mark.parametrize(
    "path",
    [
        "/proxy/api.github.com/repos/%2e%2e/gists",
        "/proxy/api.github.com/repos/%2E%2E/gists",
        "/proxy/api.github.com/repos/x%3Fy",
        "/proxy/api.github.com/repos/x%23y",
    ],
)
def test_path_that_the_client_would_rewrite_is_refused(runtime_container, client, monkeypatch, path):
    _store(runtime_container, "secret: github/prod\nallow:\n  hosts: [api.github.com]\npaths: [/repos/*]\n")
    upstream = _Upstream()
    upstream.install(monkeypatch)

    response = client.get(path, headers={"Authorization": "Bearer secret://github/prod"})

    assert response.status_code in {400, 403}
    assert upstream.calls == []


@pytest.mark.parametrize("path", ["/repos/./x", "/repos/../gists", "/repos/x#/../gists", "/repos/x?y", "/a/.."])
def test_upstream_url_must_match_the_checked_path(path):
    # The test client collapses dot segments before sending, so these raw paths are
    # checked against the verifier directly.
    with pytest.raises(ValueError):
        verified_upstream_url(ProxyTarget(scheme="https", host="api.github.com", path=path, query=""))


@pytest.mark.parametrize(
    "authority",
    [
        "api.github.com.",
        "ＡＰＩ.github.com",
        "api.gıthub.com",
        "api.github。com",
        "[::1",
        "a b.com",
        "-a.com",
        "",
    ],
)
def test_non_canonical_authorities_are_refused(authority):
    with pytest.raises(ValueError):
        _normalized_authority(authority)


# Characters that move authority boundaries in one parser or another.
_TRICKY = st.sampled_from(
    [*"#?/@\\:[]%.-_ \t\r\n", "。", "．", "ı", "ß", "​", "a", "z", "0", "9"]
)


@settings(max_examples=400, deadline=None)
@given(st.lists(st.one_of(_TRICKY, st.sampled_from(["attacker.test", "example.com", "a."])), max_size=8))
def test_fuzz_dialed_host_always_equals_policy_host(parts):
    host_header = "".join(parts)
    try:
        authority = _normalized_authority(host_header)
        url = verified_upstream_url(ProxyTarget(scheme="https", host=authority, path="/x", query=""))
    except ValueError:
        return
    dialed = url.raw_host.decode("ascii")
    assert authority.split(":")[0].strip("[]") == dialed or authority.startswith(f"[{dialed}]")
    if host_matches(authority, "*.example.com"):
        assert dialed.endswith(".example.com")


# --- Finding 4: redaction coverage ---------------------------------------------


def _reflections(secret: str) -> list[str]:
    raw = secret.encode()
    return [
        secret,
        secret.upper(),
        raw.hex(),
        raw.hex().upper(),
        json.dumps(secret)[1:-1],
        json.dumps(secret)[1:-1].replace("/", "\\/"),
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        base64.b64encode(b"user:" + raw).decode(),
        base64.b64encode(b"x" + raw + b"tail").decode(),
        base64.b64encode(b"xy" + raw).decode(),
    ]


@pytest.mark.parametrize("reflection", _reflections(SECRET_VALUE))
def test_common_reflections_are_redacted(reflection):
    engine = SecretRedactionEngine()
    engine.register(SECRET_VALUE)

    body = f'{{"echo": "{reflection}"}}'

    assert reflection not in engine.redact(body)
    assert reflection.encode() not in engine.redact_bytes(body.encode())


@settings(max_examples=200, deadline=None)
@given(
    st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=12, max_size=48),
    st.text(max_size=20),
    st.text(max_size=20),
)
def test_fuzz_reflected_secret_never_survives(secret, prefix, suffix):
    engine = SecretRedactionEngine()
    engine.register(secret)
    for reflection in _reflections(secret):
        body = prefix + reflection + suffix
        assert reflection not in engine.redact(body)


def test_agent_cannot_negotiate_an_encoding_the_broker_cannot_decode(runtime_container, client, monkeypatch):
    _store(runtime_container, "secret: github/prod\nallow:\n  hosts: [api.github.com]\n")
    upstream = _Upstream()
    upstream.install(monkeypatch)

    client.get(
        "/proxy/api.github.com/user",
        headers={"Authorization": "Bearer secret://github/prod", "Accept-Encoding": "br, zstd"},
    )

    assert upstream.calls[0]["headers"]["accept-encoding"] == "gzip, deflate"


def test_undecodable_response_encoding_fails_closed(runtime_container, client, monkeypatch):
    _store(runtime_container, "secret: github/prod\nallow:\n  hosts: [api.github.com]\n")
    upstream = _Upstream(
        httpx.Response(
            200,
            headers={"Content-Encoding": "compress", "Content-Type": "application/octet-stream"},
            content=SECRET_VALUE.encode(),
            request=httpx.Request("GET", "https://api.github.com/user"),
        )
    )
    upstream.install(monkeypatch)

    response = client.get("/proxy/api.github.com/user", headers={"Authorization": "Bearer secret://github/prod"})

    assert response.status_code == 502
    assert SECRET_VALUE not in response.text
