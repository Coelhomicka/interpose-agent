"""Transparent HTTPS_PROXY mode, end to end over real sockets and real TLS.

A fake upstream API serves TLS with a certificate from a separate test CA. The
client trusts only the broker's CA; the broker trusts only the test CA upstream.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl

import h11
import httpx
import pytest
from cryptography import x509

from interpose.core.policies import PolicyDocument
from interpose.core.scopes import project_scope
from interpose.proxy.http_proxy import create_proxy_app
from interpose.proxy.tls_authority import CertificateAuthority, write_trust_bundle
from interpose.proxy.tunnel import TunnelServer, policy_host_checker

REF = "secret://github/token"
SECRET = "ghp_tunnel_secret_value_1234567890"


class Upstream:
    """Records requests; answers with JSON that echoes the credential back."""

    def __init__(self, authority: CertificateAuthority) -> None:
        self.authority = authority
        self.requests: list[dict] = []
        self.port = 0
        self._server = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self.authority.server_context("localhost")
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        self._server.close()

    async def _handle(self, reader, writer) -> None:
        connection = h11.Connection(h11.SERVER)
        request, body = None, b""
        while True:
            event = connection.next_event()
            if event is h11.NEED_DATA:
                connection.receive_data(await reader.read(65536))
                continue
            if isinstance(event, h11.Request):
                request = event
            elif isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                break
            else:
                writer.close()
                return
        headers = {name.decode(): value.decode() for name, value in request.headers}
        self.requests.append({"target": request.target.decode(), "headers": headers, "body": body})
        payload = json.dumps({"echo": headers.get("authorization", "")}).encode()
        writer.write(connection.send(h11.Response(status_code=200, headers=[
            (b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()),
        ])))
        writer.write(connection.send(h11.Data(data=payload)))
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()
        writer.close()


def _policy(port: int, **extra) -> PolicyDocument:
    return PolicyDocument.model_validate({"secret": REF, "allow": {"hosts": [f"localhost:{port}"]}, **extra})


async def _environment(container, tmp_path, *, strict: bool = False, with_policy: bool = True):
    upstream_ca = CertificateAuthority(tmp_path / "upstream-ca")
    upstream = Upstream(upstream_ca)
    await upstream.start()
    container.secret_store.store(REF, SECRET)
    if with_policy:
        container.policy_repository.store(_policy(upstream.port))
    broker_ca = CertificateAuthority(tmp_path / "broker-ca")
    app = create_proxy_app(
        container, upstream_verify=ssl.create_default_context(cafile=str(upstream_ca.certificate_file))
    )
    tunnel = TunnelServer(
        app, broker_ca, intercepts=policy_host_checker(container.policy_repository), strict=strict,
        known_project=lambda project: container.project_registry.get(project) is not None,
    )
    port = await tunnel.start()
    return upstream, upstream_ca, broker_ca, tunnel, port


def _client(port: int, cafile, *, user: str | None = None) -> httpx.AsyncClient:
    credentials = f"{user}:x@" if user else ""
    return httpx.AsyncClient(
        proxy=f"http://{credentials}127.0.0.1:{port}",
        verify=ssl.create_default_context(cafile=str(cafile)),
        trust_env=False,
    )


def test_intercepted_host_gets_the_credential_and_the_agent_sees_it_redacted(runtime_container, tmp_path):
    async def scenario():
        upstream, _, broker_ca, tunnel, port = await _environment(runtime_container, tmp_path)
        try:
            async with _client(port, broker_ca.certificate_file) as client:
                response = await client.get(
                    f"https://localhost:{upstream.port}/user?x=1", headers={"Authorization": f"Bearer {REF}"}
                )
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream, response

    upstream, response = asyncio.run(scenario())
    assert response.status_code == 200
    assert upstream.requests[0]["headers"]["authorization"] == f"Bearer {SECRET}"
    assert upstream.requests[0]["target"] == "/user?x=1"
    assert SECRET not in response.text
    assert "[REDACTED]" in response.text
    record = runtime_container.audit_logger.list()[0]
    assert record.policy_result == "allow"
    assert record.details["transport"] == "https-proxy"


def test_policy_still_applies_inside_the_tunnel(runtime_container, tmp_path):
    async def scenario():
        upstream, _, broker_ca, tunnel, port = await _environment(runtime_container, tmp_path)
        try:
            async with _client(port, broker_ca.certificate_file) as client:
                # A body is not an injection slot: the allowed API could echo or publish it.
                return upstream, await client.post(
                    f"https://localhost:{upstream.port}/gists", json={"content": REF}
                )
        finally:
            await tunnel.close()
            await upstream.close()

    upstream, response = asyncio.run(scenario())
    assert response.status_code == 403
    assert "PolicyViolation" in response.text
    assert upstream.requests == []


def test_host_without_policy_is_tunnelled_unread(runtime_container, tmp_path):
    async def scenario():
        upstream, upstream_ca, _, tunnel, port = await _environment(runtime_container, tmp_path, with_policy=False)
        try:
            # The client must verify the *real* upstream certificate: nothing is intercepted.
            async with _client(port, upstream_ca.certificate_file) as client:
                response = await client.get(
                    f"https://localhost:{upstream.port}/", headers={"Authorization": f"Bearer {REF}"}
                )
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream, response

    upstream, response = asyncio.run(scenario())
    assert response.status_code == 200
    # Only the reference left: the agent never had the value, so it cannot leak it.
    assert upstream.requests[0]["headers"]["authorization"] == f"Bearer {REF}"


def test_strict_mode_refuses_hosts_without_policy(runtime_container, tmp_path):
    async def scenario():
        upstream, upstream_ca, _, tunnel, port = await _environment(
            runtime_container, tmp_path, strict=True, with_policy=False
        )
        try:
            async with _client(port, upstream_ca.certificate_file) as client:
                with pytest.raises(httpx.ProxyError):
                    await client.get(f"https://localhost:{upstream.port}/")
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream

    assert asyncio.run(scenario()).requests == []


def test_project_comes_from_the_proxy_user_name(runtime_container, tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    project = runtime_container.project_registry.register(root, "App")

    async def scenario():
        upstream, _, broker_ca, tunnel, port = await _environment(runtime_container, tmp_path)
        runtime_container.secret_store.store(REF, "project-value-0987654321", scope=project_scope(project.id))
        try:
            async with _client(port, broker_ca.certificate_file, user=project.id) as client:
                await client.get(f"https://localhost:{upstream.port}/", headers={"Authorization": f"Bearer {REF}"})
            async with _client(port, broker_ca.certificate_file, user="no-such-project") as client:
                with pytest.raises(httpx.ProxyError):
                    await client.get(f"https://localhost:{upstream.port}/")
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream

    upstream = asyncio.run(scenario())
    assert upstream.requests[0]["headers"]["authorization"] == "Bearer project-value-0987654321"


async def _raw_tunnel(port: int, upstream_port: int, cafile) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n".encode())
    await writer.drain()
    assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
    await writer.start_tls(ssl.create_default_context(cafile=str(cafile)), server_hostname="localhost")
    return reader, writer


def test_requests_inside_a_tunnel_must_address_the_tunnel_host(runtime_container, tmp_path):
    async def scenario():
        upstream, _, broker_ca, tunnel, port = await _environment(runtime_container, tmp_path)
        try:
            reader, writer = await _raw_tunnel(port, upstream.port, broker_ca.certificate_file)
            writer.write(f"GET / HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer {REF}\r\n\r\n".encode())
            await writer.drain()
            reply = await reader.read(4096)
            writer.close()
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream, reply

    upstream, reply = asyncio.run(scenario())
    assert reply.startswith(b"HTTP/1.1 400")
    assert upstream.requests == []


def test_scheme_override_header_is_ignored_inside_the_tunnel(runtime_container, tmp_path):
    async def scenario():
        upstream, _, broker_ca, tunnel, port = await _environment(runtime_container, tmp_path)
        try:
            async with _client(port, broker_ca.certificate_file) as client:
                response = await client.get(
                    f"https://localhost:{upstream.port}/",
                    headers={"Authorization": f"Bearer {REF}", "X-Interpose-Scheme": "http"},
                )
        finally:
            await tunnel.close()
            await upstream.close()
        return upstream, response

    upstream, response = asyncio.run(scenario())
    # Still dialled over TLS: the plain-HTTP upstream downgrade did not happen.
    assert response.status_code == 200
    assert upstream.requests[0]["headers"]["authorization"] == f"Bearer {SECRET}"


def test_origin_form_requests_are_refused(runtime_container, tmp_path):
    """A web page that reaches the proxy port sends ``GET /`` with its own Host."""

    async def scenario():
        upstream, _, _, tunnel, port = await _environment(runtime_container, tmp_path)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: rebinding.example\r\n\r\n")
            await writer.drain()
            reply = await reader.read(4096)
            writer.close()
        finally:
            await tunnel.close()
            await upstream.close()
        return reply

    assert asyncio.run(scenario()).startswith(b"HTTP/1.1 400")


def test_certificate_authority_is_constrained_and_private(tmp_path):
    public = tmp_path / "client" / "ca.pem"
    authority = CertificateAuthority(tmp_path / "ca", public_certificate=public)
    constraints = authority.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca and constraints.path_length == 0
    assert public.read_bytes() == authority.certificate_pem
    assert b"PRIVATE KEY" not in public.read_bytes()
    if os.name != "nt":
        assert (authority.key_file.stat().st_mode & 0o077) == 0

    certificate_pem, _ = authority.issue("api.github.com")
    leaf = x509.load_pem_x509_certificate(certificate_pem)
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["api.github.com"]
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    leaf.verify_directly_issued_by(authority.certificate)

    # Reloading keeps the same CA, so bundles handed to agents stay valid.
    assert CertificateAuthority(tmp_path / "ca").certificate_pem == authority.certificate_pem
    assert not list((tmp_path / "ca").glob(".leaf-*"))


def test_trust_bundle_keeps_public_roots(tmp_path):
    authority = CertificateAuthority(tmp_path / "ca")
    bundle = write_trust_bundle(authority.certificate_pem, tmp_path / "bundle.pem")
    content = bundle.read_bytes()
    assert content.endswith(authority.certificate_pem)
    assert content.count(b"BEGIN CERTIFICATE") > 50


def test_agent_environment_routes_through_the_proxy_and_trusts_only_for_the_session(tmp_path):
    from interpose.session.launcher import HttpsProxySettings, build_session_environment, https_proxy_environment
    from interpose.session.profile import SessionProfile

    settings = HttpsProxySettings(
        url="http://my-app:interpose@127.0.0.1:9877",
        ca_certificate=tmp_path / "ca.pem",
        trust_bundle=tmp_path / "bundle.pem",
    )
    environment = https_proxy_environment(settings, windows=True)
    assert environment["HTTPS_PROXY"] == environment["HTTP_PROXY"] == settings.url
    assert "127.0.0.1" in environment["NO_PROXY"]
    assert environment["NODE_EXTRA_CA_CERTS"] == str(tmp_path / "ca.pem")
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        assert environment[name] == str(tmp_path / "bundle.pem")
    git = {environment[f"GIT_CONFIG_KEY_{i}"]: environment[f"GIT_CONFIG_VALUE_{i}"]
           for i in range(int(environment["GIT_CONFIG_COUNT"]))}
    assert git == {"http.sslCAInfo": str(tmp_path / "bundle.pem"), "http.sslBackend": "openssl"}

    profile = SessionProfile.from_yaml("version: 1\nenvironment: {}\n")
    session = build_session_environment(
        profile, agent="a", session="s", source={"HTTPS_PROXY": "http://elsewhere:1"}, https_proxy=settings
    )
    assert session["HTTPS_PROXY"] == settings.url

    explicit = SessionProfile.from_yaml(
        "version: 1\nenvironment: {}\nruntime:\n  http_proxy: http://127.0.0.1:3128\n"
    )
    session = build_session_environment(explicit, agent="a", session="s", source={}, https_proxy=settings)
    assert "HTTPS_PROXY" not in session and session["HTTP_PROXY"] == "http://127.0.0.1:3128"


def test_curl_config_keeps_the_users_own_and_adds_the_bundle(tmp_path, monkeypatch):
    from interpose.session.launcher import write_curl_config

    user_home = tmp_path / "user"
    user_home.mkdir()
    (user_home / ".curlrc").write_text("user-agent = mine\n", encoding="utf-8")
    for name in ("CURL_HOME", "XDG_CONFIG_HOME", "APPDATA", "USERPROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(user_home))

    directory = write_curl_config(tmp_path / "curl", tmp_path / "bundle dir" / "b.pem", windows=True)
    content = (directory / "_curlrc").read_text(encoding="utf-8")
    assert content.splitlines() == [
        "user-agent = mine",
        f'cacert = "{(tmp_path / "bundle dir" / "b.pem").as_posix()}"',
        "ssl-revoke-best-effort",
    ]
    assert (directory / ".curlrc").read_text(encoding="utf-8") == content


def test_endpoint_file_from_an_older_service_still_loads():
    from interpose.service.client import https_proxy_url
    from interpose.service.layout import ServiceEndpoint

    old = ServiceEndpoint.from_json('{"proxy_url": "http://127.0.0.1:9876", "dashboard_url": "d", "pid": 4}')
    assert old.https_proxy_url is None
    new = ServiceEndpoint("p", "d", 1, "http://127.0.0.1:9877")
    assert ServiceEndpoint.from_json(new.to_json()) == new
    assert https_proxy_url("http://127.0.0.1:9877", "my-app") == "http://my-app:interpose@127.0.0.1:9877"
    assert https_proxy_url("http://127.0.0.1:9877", None) == "http://127.0.0.1:9877"
