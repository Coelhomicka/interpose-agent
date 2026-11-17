"""Transparent ``HTTPS_PROXY`` front for the broker.

Most tools (``gh``, ``git``, ``curl``, ``npm``, SDKs, MCP servers) cannot be
pointed at the broker's ``/proxy/<host>/...`` URLs, but nearly all honor
``HTTPS_PROXY``. This server speaks that protocol:

* ``CONNECT host:port`` to a host some policy names: the broker answers the TLS
  itself with a certificate from its local CA (see ``tls_authority``), reads each
  request, and hands it to the same ASGI broker app as the explicit transport,
  so policy, slot checks, substitution, redaction and audit are identical.
* ``CONNECT`` to any other host: a plain byte tunnel, unread. The agent holds no
  credential, so nothing it sends there can contain one. ``strict`` refuses these.
* Absolute-form ``http://`` requests (``HTTP_PROXY``): handed to the broker app.

The project scope travels as the proxy user name
(``HTTPS_PROXY=http://<project-id>@127.0.0.1:9877``); like the ``/p/<id>``
route, it selects configuration and is not an isolation boundary.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

import h11

from ..core.policies import SQLitePolicyRepository, host_matches
from .http_proxy import _normalized_authority
from .tls_authority import CertificateAuthority

logger = logging.getLogger("interpose.tunnel")

MAX_BODY_BYTES = 32 * 1024 * 1024
READ_CHUNK = 64 * 1024
IDLE_TIMEOUT = 120.0
_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def policy_host_checker(repository: SQLitePolicyRepository) -> Callable[[str], bool]:
    """Whether any stored policy, in any scope, allows ``host``.

    Scopes are not a boundary (a process can name any project), so the union is
    the honest answer to "could a credential be injected for this host?".
    """
    from ..core.policies import PolicyDocument, PolicyError

    def intercepts(host: str) -> bool:
        for record in repository.list():
            try:
                document = PolicyDocument.from_yaml(record.definition)
            except PolicyError:
                continue
            if document.allow and any(host_matches(host, pattern) for pattern in document.allow.hosts):
                return True
        return False

    return intercepts


def _policy_authority(authority: str, scheme: str) -> str:
    """``host[:port]`` as policies write it: the default port is left out."""
    default = ":443" if scheme == "https" else ":80"
    return authority[: -len(default)] if authority.endswith(default) else authority


def _dial_address(authority: str) -> tuple[str, int]:
    parsed = urlsplit(f"//{authority}")
    if parsed.hostname is None or parsed.port is None:
        raise ValueError("CONNECT target needs host:port")
    return parsed.hostname, parsed.port


def _project_from(headers: list[tuple[bytes, bytes]]) -> str | None:
    for name, value in headers:
        if name.lower() != b"proxy-authorization":
            continue
        scheme, _, encoded = value.decode("latin-1").partition(" ")
        if scheme.lower() != "basic":
            raise ValueError("unsupported proxy authorization")
        try:
            user = base64.b64decode(encoded.strip(), validate=True).decode("utf-8").partition(":")[0]
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid proxy authorization") from exc
        user = unquote(user).strip().lower()
        if user in {"", "global"}:
            return None
        if not _PROJECT_RE.match(user):
            raise ValueError("invalid project in proxy user name")
        return user
    return None


@dataclass
class TunnelServer:
    """``app`` is the broker ASGI app; ``authority`` signs the per-host certificates."""

    app: Any
    authority: CertificateAuthority
    intercepts: Callable[[str], bool]
    strict: bool = False
    known_project: Callable[[str], bool] = field(default=lambda project: True)
    _server: Any = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self._server = await asyncio.start_server(self._handle, host, port)
        return int(self._server.sockets[0].getsockname()[1])

    async def serve_until(self, stop: Callable[[], bool], host: str, port: int) -> None:
        await self.start(host, port)
        try:
            while not stop():
                await asyncio.sleep(0.2)
        finally:
            await self.close()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

    # -- connection handling -------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._handle_outer(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError, ssl.SSLError):
            pass
        except Exception:  # pragma: no cover - last resort, never crash the server
            logger.exception("tunnel connection failed")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle_outer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = h11.Connection(h11.SERVER, max_incomplete_event_size=READ_CHUNK)
        event = await _next_event(connection, reader)
        if not isinstance(event, h11.Request):
            return
        try:
            project = _project_from(event.headers)
        except ValueError as exc:
            await _write_simple(writer, 407, str(exc))
            return
        if project is not None and not self.known_project(project):
            await _write_simple(writer, 403, f"unknown project: {project}")
            return

        if event.method == b"CONNECT":
            await self._connect(event, project, reader, writer)
            return
        # Absolute-form plain HTTP (HTTP_PROXY). Origin-form ("GET /") is what a web
        # page reaching this port would send; the proxy never serves those.
        target = event.target.decode("ascii", errors="replace")
        if not target.lower().startswith("http://"):
            await _write_simple(writer, 400, "this is a proxy: send absolute-form http:// requests or CONNECT")
            return
        await self._serve_requests(connection, event, reader, writer, project=project, fixed_authority=None)

    async def _connect(
        self,
        event: h11.Request,
        project: str | None,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            authority = _normalized_authority(event.target.decode("ascii"))
            dial_host, dial_port = _dial_address(authority)
        except (ValueError, UnicodeDecodeError):
            await _write_simple(writer, 400, "invalid CONNECT target")
            return
        policy_host = _policy_authority(authority, "https")

        if self.intercepts(policy_host):
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await writer.start_tls(self.authority.server_context(policy_host))
            inner = h11.Connection(h11.SERVER, max_incomplete_event_size=READ_CHUNK)
            first = await _next_event(inner, reader)
            if not isinstance(first, h11.Request):
                return
            await self._serve_requests(inner, first, reader, writer, project=project, fixed_authority=policy_host)
            return

        if self.strict:
            await _write_simple(writer, 403, f"{policy_host} has no policy and the proxy is in strict mode")
            return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(dial_host, dial_port), timeout=15
            )
        except (OSError, TimeoutError):
            await _write_simple(writer, 502, f"cannot reach {authority}")
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.gather(_pipe(reader, upstream_writer), _pipe(upstream_reader, writer))
        finally:
            upstream_writer.close()

    async def _serve_requests(
        self,
        connection: h11.Connection,
        request: h11.Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        project: str | None,
        fixed_authority: str | None,
    ) -> None:
        """Answer requests on one connection until either side ends it.

        ``fixed_authority`` is the CONNECT target inside a TLS tunnel: every request
        there must name it in ``Host``, so a client cannot open a tunnel to one host
        and address another (the certificate and the policy check would disagree).
        """
        while True:
            body = bytearray()
            while True:
                event = await _next_event(connection, reader)
                if isinstance(event, h11.Data):
                    body += event.data
                    if len(body) > MAX_BODY_BYTES:
                        await _send(connection, writer, 413, b"request body too large")
                        return
                elif isinstance(event, h11.EndOfMessage):
                    break
                else:
                    return

            try:
                scope = self._scope(request, project=project, fixed_authority=fixed_authority, writer=writer)
            except ValueError as exc:
                await _send(connection, writer, 400, str(exc).encode())
                return
            status, headers, content = await _call_asgi(self.app, scope, bytes(body))
            if request.method == b"HEAD":
                content = b""
            await _send(connection, writer, status, content, headers=headers, head=request.method == b"HEAD")

            if connection.our_state is h11.MUST_CLOSE or connection.their_state is h11.MUST_CLOSE:
                return
            try:
                connection.start_next_cycle()
            except h11.LocalProtocolError:
                return
            event = await _next_event(connection, reader)
            if not isinstance(event, h11.Request):
                return
            request = event

    def _scope(
        self,
        request: h11.Request,
        *,
        project: str | None,
        fixed_authority: str | None,
        writer: asyncio.StreamWriter,
    ) -> dict[str, Any]:
        target = request.target.decode("ascii", errors="strict")
        host_header = next((value for name, value in request.headers if name == b"host"), None)
        if fixed_authority is not None:
            if not target.startswith("/"):
                raise ValueError("requests inside a tunnel must use origin-form targets")
            if host_header is None:
                raise ValueError("missing Host header")
            host = _policy_authority(_normalized_authority(host_header.decode("ascii")), "https")
            if host != fixed_authority:
                raise ValueError("Host does not match the CONNECT target")
            scheme = "https"
            path, _, query = target.partition("?")
            raw_target = f"https://{fixed_authority}{path}"
        else:
            parsed = urlsplit(target)
            scheme = parsed.scheme.lower()
            path, query = parsed.path or "/", parsed.query
            raw_target = f"{scheme}://{parsed.netloc}{path}"

        headers = [
            (name.lower(), value)
            for name, value in request.headers
            # The scheme override is for the Host-header deployment behind a trusted
            # front; inside the tunnel the scheme is fixed by the transport.
            if name.lower() not in {b"proxy-authorization", b"proxy-connection", b"x-interpose-scheme"}
        ]
        peer = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        return {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": request.method.decode("ascii"),
            "scheme": scheme,
            "path": "/" + unquote(path).lstrip("/"),
            "raw_path": raw_target.encode("ascii"),
            "query_string": query.encode("ascii"),
            "root_path": "",
            "headers": headers,
            "client": (str(peer[0]), int(peer[1])),
            "server": ("127.0.0.1", 0),
            "state": {},
            "interpose.project": project,
            "interpose.transport": "https-proxy" if fixed_authority else "http-proxy",
        }


async def _next_event(connection: h11.Connection, reader: asyncio.StreamReader):
    while True:
        try:
            event = connection.next_event()
        except h11.RemoteProtocolError:
            return None
        if event is h11.NEED_DATA:
            data = await asyncio.wait_for(reader.read(READ_CHUNK), timeout=IDLE_TIMEOUT)
            connection.receive_data(data)
            continue
        if event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
            return event if isinstance(event, h11.Request) else None
        return event


async def _write_simple(writer: asyncio.StreamWriter, status: int, message: str) -> None:
    body = message.encode("utf-8")
    reason = {400: "Bad Request", 403: "Forbidden", 407: "Proxy Authentication Required", 502: "Bad Gateway"}
    writer.write(
        f"HTTP/1.1 {status} {reason.get(status, 'Error')}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        .encode("ascii")
        + body
    )
    await writer.drain()


async def _send(
    connection: h11.Connection,
    writer: asyncio.StreamWriter,
    status: int,
    content: bytes,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    head: bool = False,
) -> None:
    if headers is None:
        headers = [(b"content-type", b"text/plain; charset=utf-8")]
    framing = {b"content-length", b"transfer-encoding"}
    headers = [(name, value) for name, value in headers if name.lower() not in framing]
    if not head:
        headers.append((b"content-length", str(len(content)).encode("ascii")))
    try:
        writer.write(connection.send(h11.Response(status_code=status, headers=headers)))
        if content:
            writer.write(connection.send(h11.Data(data=content)))
        writer.write(connection.send(h11.EndOfMessage()))
    except h11.LocalProtocolError:
        return
    await writer.drain()


async def _call_asgi(app: Any, scope: dict[str, Any], body: bytes) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    sent = False
    status = 500
    headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.Event().wait()  # pragma: no cover - the broker reads the body once
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status, headers
        if message["type"] == "http.response.start":
            status = int(message["status"])
            headers = [(bytes(name), bytes(value)) for name, value in message.get("headers", [])]
        elif message["type"] == "http.response.body":
            chunks.append(bytes(message.get("body", b"")))

    await app(scope, receive, send)
    return status, headers, b"".join(chunks)


async def _pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
    try:
        while data := await source.read(READ_CHUNK):
            destination.write(data)
            await destination.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if destination.can_write_eof():
                destination.write_eof()
