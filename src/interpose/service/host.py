"""The service process: broker and dashboard on loopback, vault in the service's folder.

Started by the Windows service manager as::

    "C:\\Program Files\\Interpose\\python\\python.exe" -I -m interpose.service.host

``--console`` runs the same thing in the foreground, for debugging an install.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import secrets
import sys
import threading
from pathlib import Path

import uvicorn

from ..config import RuntimeConfig
from ..container import create_container
from ..core.presence import PresenceVerifier
from ..dashboard.app import DashboardAuth, DashboardContext, create_dashboard_app
from ..proxy.http_proxy import create_proxy_app
from . import SERVICE_NAME
from .layout import DEFAULT_DASHBOARD_PORT, DEFAULT_PROXY_PORT, ServiceEndpoint, ServiceLayout

logger = logging.getLogger("interpose.service")


def _write_atomically(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def publish_endpoint(layout: ServiceLayout, endpoint: ServiceEndpoint, control_token: str) -> None:
    """Tell clients where the service listens and how to drive it.

    The control token goes first, so a client that sees the endpoint file can
    always read a token that matches it.
    """
    layout.client_dir.mkdir(parents=True, exist_ok=True)
    _write_atomically(layout.control_token_file, control_token)
    _write_atomically(layout.endpoint_file, endpoint.to_json())


def withdraw_endpoint(layout: ServiceLayout) -> None:
    for path in (layout.endpoint_file, layout.control_token_file):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def run_host(
    layout: ServiceLayout,
    stop_event: threading.Event,
    *,
    proxy_port: int = DEFAULT_PROXY_PORT,
    dashboard_port: int = DEFAULT_DASHBOARD_PORT,
) -> None:
    layout.vault_dir.mkdir(parents=True, exist_ok=True)
    # The vault folder is this process's runtime home. An inherited master key
    # would bypass the protected key file, so it is never honoured here.
    os.environ["INTERPOSE_HOME"] = str(layout.vault_dir)
    os.environ.pop("INTERPOSE_MASTER_KEY", None)
    container = create_container(RuntimeConfig.from_env())

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    dashboard_url = f"http://127.0.0.1:{dashboard_port}"
    control_token = secrets.token_urlsafe(32)
    dashboard = create_dashboard_app(
        container,
        DashboardContext(working_directory=None, proxy_url=proxy_url, follow_project=False),
        DashboardAuth(default_token=False),
        control_token=control_token,
        presence=PresenceVerifier(layout.presence_file),
    )
    servers = [
        uvicorn.Server(uvicorn.Config(create_proxy_app(container), host="127.0.0.1", port=proxy_port,
                                      log_level="warning", log_config=None)),
        uvicorn.Server(uvicorn.Config(dashboard, host="127.0.0.1", port=dashboard_port,
                                      log_level="warning", log_config=None)),
    ]

    async def serve() -> None:
        async def publish_when_ready() -> None:
            while not all(server.started for server in servers):
                await asyncio.sleep(0.05)
            publish_endpoint(layout, ServiceEndpoint(proxy_url, dashboard_url, os.getpid()), control_token)
            logger.info("listening: proxy %s, dashboard %s", proxy_url, dashboard_url)

        async def stop_when_asked() -> None:
            while not stop_event.is_set():
                await asyncio.sleep(0.2)
            for server in servers:
                server.should_exit = True

        await asyncio.gather(*(server.serve() for server in servers), publish_when_ready(), stop_when_asked())

    try:
        asyncio.run(serve())
    finally:
        withdraw_endpoint(layout)
        logger.info("stopped")


def _log_to_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = open(path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - lives as long as the process
    # A service has no console; anything printed must not fail or vanish.
    sys.stdout = sys.stderr = stream
    logging.basicConfig(
        stream=stream,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="interpose-service")
    parser.add_argument("--console", action="store_true", help="Run in the foreground instead of under the SCM.")
    parser.add_argument("--data-dir", type=Path, help="Override the service data folder (console runs only).")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    parser.add_argument("--dashboard-port", type=int, default=DEFAULT_DASHBOARD_PORT)
    args = parser.parse_args(argv)

    layout = ServiceLayout.default()
    ports = {"proxy_port": args.proxy_port, "dashboard_port": args.dashboard_port}

    if args.console:
        if args.data_dir is not None:
            layout = ServiceLayout(program_dir=layout.program_dir, data_dir=args.data_dir)
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        stop_event = threading.Event()
        try:
            run_host(layout, stop_event, **ports)
        except KeyboardInterrupt:
            stop_event.set()
        return 0

    from .winsvc import run_service

    _log_to_file(layout.log_file)

    def body(stop_event: threading.Event) -> None:
        try:
            run_host(layout, stop_event, **ports)
        except BaseException:
            logger.exception("service failed")
            raise

    run_service(SERVICE_NAME, body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
