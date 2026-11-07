from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import tempfile
import webbrowser
from pathlib import Path

import typer
import uvicorn

from ..api.app import create_app, generate_admin_token
from ..container import create_container
from ..core.local_guard import require_loopback_bind
from ..core.policies import PolicyDocument, PolicyError
from ..core.references import SecretReferenceError, normalize_secret_reference
from ..executor.trusted_executor import ExecutionPreparationError, PolicyViolationError
from ..proxy.http_proxy import create_proxy_app
from ..secrets.base import SecretNotFound, SecretValueError
from ..service.layout import DEFAULT_PROXY_PORT, ServiceLayout, service_installed
from ..session.dotenv import DotenvValidationError, validate_dotenv
from ..session.isolation.base import IsolationError
from ..session.isolation.factory import create_isolation_backend
from ..session.launcher import SessionLauncher, SessionLaunchError
from ..session.profile import SessionProfile, SessionProfileError

app = typer.Typer(add_completion=False, help="Administrative CLI for Interpose")
secret_app = typer.Typer(add_completion=False, help="Secret management commands")
profile_app = typer.Typer(add_completion=False, help="Session profile commands")
env_app = typer.Typer(add_completion=False, help="Reference-only .env commands")
policy_app = typer.Typer(add_completion=False, help="Policy administration commands")
isolation_app = typer.Typer(add_completion=False, help="Process and network isolation commands")
service_app = typer.Typer(add_completion=False, help="Install and control the Interpose OS service")
interpose_exec_app = typer.Typer(
    add_completion=False,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Trusted executor for untrusted commands",
)

app.add_typer(secret_app, name="secret")
app.add_typer(profile_app, name="profile")
app.add_typer(env_app, name="env")
app.add_typer(policy_app, name="policy")
app.add_typer(isolation_app, name="isolation")
app.add_typer(service_app, name="service")


def _container():
    if service_installed():
        # The vault belongs to the service account now; this user cannot open it,
        # which is the point. Configuration goes through the dashboard.
        typer.echo(
            "The vault is managed by the Interpose service. Use `interpose up` to open the dashboard.",
            err=True,
        )
        raise typer.Exit(code=1)
    # The registered project containing the current folder, if any, becomes the
    # active scope: its secrets and policies resolve before the global ones.
    return create_container(project_root=Path.cwd())


class _ServiceReferences:
    """Ask the service whether a reference exists, from a given folder's scope."""

    def __init__(self, client, working_directory: Path) -> None:
        self._client = client
        self._working_directory = working_directory

    def exists(self, reference: str) -> bool:
        return self._client.secret_exists(reference, self._working_directory)


def _session_launcher(cwd: Path | None) -> SessionLauncher:
    working_directory = (cwd or Path.cwd()).resolve()
    if service_installed():
        from ..service.client import ServiceClient, ServiceUnavailable

        try:
            client = ServiceClient.connect()
            client.verify_identity()
            proxy_base = client.proxy_base(working_directory)
        except ServiceUnavailable as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        return SessionLauncher(
            secret_store=_ServiceReferences(client, working_directory),
            audit_logger=None,
            runtime_home=Path.home() / ".interpose",
            proxy_base=proxy_base,
        )
    container = create_container(project_root=working_directory)
    project = container.project
    port = os.environ.get("INTERPOSE_PROXY_PORT", str(DEFAULT_PROXY_PORT))
    prefix = f"/p/{project.id}" if project else ""
    launcher = container.session_launcher
    launcher.proxy_base = f"http://127.0.0.1:{port}{prefix}/proxy"
    return launcher


@secret_app.command("add")
def secret_add(reference: str) -> None:
    container = _container()
    secret_value = typer.prompt("Secret", hide_input=True)
    try:
        normalized_reference = normalize_secret_reference(reference)
        metadata = container.secret_store.store(normalized_reference, secret_value)
    except SecretReferenceError as exc:
        typer.echo(f"Invalid secret reference: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except SecretValueError as exc:
        typer.echo(f"Invalid secret value: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Secret stored:")
    typer.echo(metadata.reference)


@secret_app.command("list")
def secret_list() -> None:
    container = _container()
    typer.echo("NAME")
    for metadata in container.secret_store.list_metadata():
        typer.echo(metadata.reference.removeprefix("secret://"))


@secret_app.command("delete")
def secret_delete(identifier: str) -> None:
    container = _container()
    target: str | int
    if identifier.isdigit():
        target = int(identifier)
    else:
        try:
            target = normalize_secret_reference(identifier)
        except SecretReferenceError as exc:
            typer.echo(f"Invalid secret reference: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    if not container.secret_store.delete(target):
        raise typer.Exit(code=1)


@secret_app.command("inspect")
def secret_inspect(identifier: str) -> None:
    container = _container()
    metadata = None
    if identifier.isdigit():
        target_id = int(identifier)
        metadata = next((item for item in container.secret_store.list_metadata() if item.id == target_id), None)
    else:
        try:
            reference = normalize_secret_reference(identifier)
        except SecretReferenceError as exc:
            typer.echo(f"Invalid secret reference: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        metadata = next((item for item in container.secret_store.list_metadata() if item.reference == reference), None)
    if metadata is None:
        raise typer.Exit(code=1)
    typer.echo(json.dumps(
        {
            "id": metadata.id,
            "reference": metadata.reference,
            "provider": metadata.provider,
            "namespace": metadata.namespace,
            "path": metadata.path,
            "fingerprint": metadata.fingerprint,
            "created_at": metadata.created_at.isoformat(),
            "updated_at": metadata.updated_at.isoformat(),
        },
        indent=2,
    ))


@profile_app.command("validate")
def profile_validate(path: Path) -> None:
    try:
        profile = SessionProfile.from_path(path)
        _session_launcher(None).validate_bindings(profile)
    except (SessionProfileError, SessionLaunchError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Profile valid: {path}")


@profile_app.command("env")
def profile_environment(path: Path) -> None:
    try:
        profile = SessionProfile.from_path(path)
    except SessionProfileError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    for name, reference in sorted(profile.environment.items()):
        typer.echo(f"{name}={reference}")


@env_app.command("validate")
def env_validate(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        validate_dotenv(path, session_profile)
    except (SessionProfileError, DotenvValidationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Reference-only environment valid: {path}")


@policy_app.command("add")
def policy_add(path: Path) -> None:
    try:
        document = PolicyDocument.from_yaml(path.read_text(encoding="utf-8"))
        record = _container().policy_repository.store(document)
    except (OSError, PolicyError) as exc:
        typer.echo(f"Invalid policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Policy stored: {record.id} {record.secret_reference}")


@policy_app.command("list")
def policy_list() -> None:
    typer.echo("ID SECRET")
    for record in _container().policy_repository.list():
        typer.echo(f"{record.id} {record.secret_reference}")


@policy_app.command("delete")
def policy_delete(policy_id: int) -> None:
    if not _container().policy_repository.delete(policy_id):
        typer.echo("Policy not found", err=True)
        raise typer.Exit(code=1)


@policy_app.command("inspect")
def policy_inspect(policy_id: int) -> None:
    record = _container().policy_repository.get(policy_id)
    if record is None:
        typer.echo("Policy not found", err=True)
        raise typer.Exit(code=1)
    typer.echo(record.definition)


@isolation_app.command("doctor")
def isolation_doctor(
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        container = _container()
        backend = create_isolation_backend(
            session_profile.runtime.isolation,
            session="doctor",
            runtime_home=container.config.paths.home,
        )
    except (SessionProfileError, IsolationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    doctor = getattr(backend, "doctor", None)
    if doctor is None:
        typer.echo("FAIL isolation: profile does not enable an enforced isolation backend", err=True)
        raise typer.Exit(code=1)
    checks = doctor()
    for name, passed, detail in checks:
        typer.echo(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
    if not all(passed for _, passed, _ in checks):
        raise typer.Exit(code=1)


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run_session(
    ctx: typer.Context,
    profile: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    agent: str = typer.Option(
        "unknown",
        help="Audit label only; no policy or behavior depends on it. Not propagated to the broker.",
    ),
    session: str | None = typer.Option(None, help="Optional session identifier"),
    cwd: Path | None = typer.Option(None, exists=True, file_okay=False),
) -> None:
    try:
        session_profile = SessionProfile.from_path(profile)
        return_code = _session_launcher(cwd).run(
            list(ctx.args),
            profile=session_profile,
            agent=agent,
            session=session,
            cwd=cwd,
        )
    except (SessionProfileError, SessionLaunchError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    raise typer.Exit(code=return_code)


def _loopback_or_exit(host: str) -> None:
    try:
        require_loopback_bind(host)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command("api")
def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    _loopback_or_exit(host)
    token = generate_admin_token()
    # Shown once, on the operator's terminal only. It is not persisted anywhere an
    # agent running as the same user could read it back.
    typer.echo(f"Admin API token (send as 'Authorization: Bearer <token>'): {token}", err=True)
    uvicorn.run(create_app(admin_token=token), host=host, port=port, log_level="info")


@app.command("proxy")
def run_proxy(host: str = "127.0.0.1", port: int = 9876) -> None:
    _loopback_or_exit(host)
    uvicorn.run(create_proxy_app(_container()), host=host, port=port, log_level="info")


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@app.command("up")
def up(
    project_dir: Path = typer.Option(Path("."), "--project-dir", exists=True, file_okay=False,
                                     help="Folder whose project scope is active."),
    proxy_port: int = typer.Option(9876, help="Broker port agents connect to."),
    dashboard_port: int = typer.Option(18888, help="Dashboard port; a free one is chosen if taken."),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open the dashboard in the browser."),
) -> None:
    """Start the broker and the configuration dashboard together, like `aspire run`."""
    from ..dashboard.app import DashboardAuth, DashboardContext, create_dashboard_app

    working_directory = project_dir.resolve()
    if service_installed():
        _open_service_dashboard(working_directory, open_browser)
        return
    container = create_container(project_root=working_directory)
    if not _port_is_free(proxy_port):
        typer.echo(f"Port {proxy_port} is in use; pass --proxy-port to choose another.", err=True)
        raise typer.Exit(code=1)
    if not _port_is_free(dashboard_port):
        dashboard_port = _free_port()

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    auth = DashboardAuth()
    dashboard = create_dashboard_app(container, DashboardContext(working_directory, proxy_url), auth)
    login_url = f"http://127.0.0.1:{dashboard_port}/login?t={auth.login_token}"

    project = container.project
    typer.echo("")
    typer.secho("  Interpose", bold=True)
    typer.echo(f"  Project:    {project.name} ({project.root})" if project else
               f"  Project:    none - global scope only ({working_directory})")
    typer.echo(f"  Proxy:      {proxy_url}")
    typer.echo(f"  Dashboard:  {login_url}")
    typer.echo("              (single-use login link; restart for a new one)")
    typer.echo("")
    if os.name == "nt":
        typer.secho(
            "  Development mode: the vault in your profile is readable by any program running as you,\n"
            "  agents included. Run `interpose setup` once to move it into a protected OS service.",
            fg=typer.colors.YELLOW,
        )
        typer.echo("")
    typer.echo("  Press Ctrl+C to stop.", err=True)

    servers = [
        uvicorn.Server(uvicorn.Config(create_proxy_app(container), host="127.0.0.1", port=proxy_port,
                                      log_level="warning")),
        uvicorn.Server(uvicorn.Config(dashboard, host="127.0.0.1", port=dashboard_port, log_level="warning")),
    ]

    async def serve() -> None:
        async def open_when_ready() -> None:
            while not servers[1].started:
                await asyncio.sleep(0.05)
            if open_browser:
                webbrowser.open(login_url)

        await asyncio.gather(*(server.serve() for server in servers), open_when_ready())

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve())


def _open_service_dashboard(working_directory: Path, open_browser: bool) -> None:
    from ..service.client import ServiceClient, ServiceUnavailable

    try:
        client = ServiceClient.connect()
        client.verify_identity()
        login_url = client.login_url(working_directory)
        project_id = client.project_id(working_directory)
    except ServiceUnavailable as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("")
    typer.secho("  Interpose (service)", bold=True)
    typer.echo(f"  Project:    {project_id or 'none - global scope only'} ({working_directory})")
    typer.echo(f"  Proxy:      {client.proxy_base(working_directory)}")
    typer.echo(f"  Dashboard:  {login_url}")
    typer.echo("              (single-use login link, valid for 5 minutes)")
    typer.echo("")
    if open_browser:
        webbrowser.open(login_url)


# --------------------------------------------------------------------------- service


def _run_service_task(task: str, **options: str | bool) -> None:
    """Run an install/uninstall/start/stop task elevated, showing its log."""
    from ..service.install import InstallError, is_elevated, run_elevated

    if os.name != "nt":
        typer.echo("The Interpose service is only available on Windows for now.", err=True)
        raise typer.Exit(code=1)
    descriptor, log_name = tempfile.mkstemp(prefix="interpose-setup-", suffix=".log")
    os.close(descriptor)  # the elevated child writes it; an open handle here would block the cleanup
    log_file = Path(log_name)
    arguments = ["-m", "interpose.cli.main", "service", "elevated", task, "--log", str(log_file)]
    for name, value in options.items():
        flag = "--" + name.replace("_", "-")
        if isinstance(value, bool):
            if value:
                arguments.append(flag)
        else:
            arguments += [flag, value]
    if task in {"install", "uninstall"}:
        typer.echo("Windows will ask for administrator approval once.")
    if task == "install":
        typer.echo("Installing: copies a private Python runtime and downloads dependencies (1-3 minutes)...")
    try:
        if is_elevated():
            code = _elevated_task(task, log_file=log_file, echo=True, **options)
        else:
            code = run_elevated(arguments)
            typer.echo(log_file.read_text(encoding="utf-8", errors="replace"), nl=False)
    except InstallError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    finally:
        log_file.unlink(missing_ok=True)
    if code != 0:
        raise typer.Exit(code=code)


def _elevated_task(task: str, *, log_file: Path, echo: bool = False, **options) -> int:
    from ..service.install import InstallError, install, uninstall

    layout = ServiceLayout.default()
    with open(log_file, "a", encoding="utf-8") as stream:
        def log(message: str) -> None:
            stream.write(message + "\n")
            stream.flush()
            if echo:
                typer.echo(message)

        try:
            if task == "install":
                install(layout, user_sid=options["user_sid"], user_home=Path(options["user_home"]),
                        source=options["source"], keep_user_vault=bool(options.get("keep_user_vault")), log=log)
            elif task == "uninstall":
                uninstall(layout, purge=bool(options.get("purge")), log=log)
            elif task in {"start", "stop"}:
                import subprocess

                from ..service import SERVICE_NAME

                result = subprocess.run(["sc", task, SERVICE_NAME], capture_output=True, text=True, check=False)
                log(f"sc {task}: exit {result.returncode}")
                return 0 if result.returncode == 0 else 1
            else:
                log(f"unknown task: {task}")
                return 2
        except (InstallError, OSError) as exc:
            log(f"error: {exc}")
            return 1
    return 0


def _preflight_install() -> None:
    from ..service.win32 import listener_pid, service_pid

    if os.environ.get("INTERPOSE_MODE") == "reference-only":
        typer.echo("Refusing to install from inside an `interpose run` session; run setup yourself.", err=True)
        raise typer.Exit(code=1)
    if os.environ.get("INTERPOSE_MASTER_KEY"):
        typer.echo("INTERPOSE_MASTER_KEY is set; the service only uses a protected key file. Unset it first.",
                   err=True)
        raise typer.Exit(code=1)
    service = service_pid()
    for port in (DEFAULT_PROXY_PORT, 18888):
        owner = listener_pid(port)
        if owner is not None and owner != service:
            typer.echo(f"Port {port} is in use by process {owner} (an `interpose up` still running?). "
                       "Stop it and run setup again.", err=True)
            raise typer.Exit(code=1)


@app.command("setup")
def setup(
    keep_user_vault: bool = typer.Option(False, help="Copy the development vault instead of moving it."),
    source: str | None = typer.Option(None, help="What to pip-install into the service (default: this install)."),
) -> None:
    """Install Interpose as a Windows service (one administrator prompt)."""
    from ..config import _current_user_sid
    from ..service.install import default_source

    if os.name == "nt":
        _preflight_install()
    _run_service_task(
        "install",
        user_sid=_current_user_sid(),
        user_home=str(Path.home()),
        source=source or default_source(),
        keep_user_vault=keep_user_vault,
    )
    typer.echo("Done. Run `interpose up` in a project folder to open the dashboard.")


@service_app.command("install")
def service_install(
    keep_user_vault: bool = typer.Option(False, help="Copy the development vault instead of moving it."),
    source: str | None = typer.Option(None, help="What to pip-install into the service (default: this install)."),
) -> None:
    """Same as `interpose setup`."""
    setup(keep_user_vault=keep_user_vault, source=source)


@service_app.command("uninstall")
def service_uninstall(
    purge: bool = typer.Option(False, help="Also destroy the vault. Every stored secret is lost."),
) -> None:
    """Remove the service. The vault is kept unless --purge is given."""
    if purge and not typer.confirm("Destroy the vault and every secret in it? This cannot be undone"):
        raise typer.Exit(code=1)
    _run_service_task("uninstall", purge=purge)


@service_app.command("start")
def service_start() -> None:
    _run_service_task("start")


@service_app.command("stop")
def service_stop() -> None:
    _run_service_task("stop")


@service_app.command("status")
def service_status_command() -> None:
    from ..service.win32 import service_status

    layout = ServiceLayout.default()
    status = service_status() if os.name == "nt" else None
    if status is None:
        typer.echo("Not installed (development mode: the vault is in your profile).")
        raise typer.Exit(code=1)
    states = {1: "stopped", 2: "starting", 3: "stopping", 4: "running"}
    typer.echo(f"Service:  {states.get(status[0], status[0])} (pid {status[1] or '-'})")
    typer.echo(f"Runtime:  {layout.program_dir}")
    typer.echo(f"Vault:    {layout.vault_dir}")
    if layout.endpoint_file.is_file():
        typer.echo(f"Endpoint: {layout.endpoint_file.read_text(encoding='utf-8')}")


@service_app.command("elevated", hidden=True)
def service_elevated(
    task: str,
    log: Path = typer.Option(...),
    user_sid: str = typer.Option(""),
    user_home: str = typer.Option(""),
    source: str = typer.Option(""),
    keep_user_vault: bool = typer.Option(False),
    purge: bool = typer.Option(False),
) -> None:
    """Internal: the part of a service task that runs behind the UAC prompt."""
    code = _elevated_task(task, log_file=log, user_sid=user_sid, user_home=user_home, source=source,
                          keep_user_vault=keep_user_vault, purge=purge)
    raise typer.Exit(code=code)


@interpose_exec_app.command()
def interpose_exec(
    ctx: typer.Context,
    agent: str = typer.Option(
        "unknown",
        help="Audit label only; no policy or behavior depends on it.",
    ),
    destination: str | None = typer.Option(None, help="Explicit destination host"),
    method: str | None = typer.Option(None, help="Explicit method"),
    session: str = typer.Option("local", help="Session identifier"),
) -> None:
    command = list(ctx.args)
    container = _container()
    try:
        if destination:
            from ..models import DestinationContext

            destination_context = DestinationContext(host=destination, method=(method or "EXEC").upper())
        else:
            destination_context = None
        result = container.executor.execute(
            command,
            session=session,
            agent=agent,
            destination=destination_context,
        )
        if result.stdout:
            typer.echo(result.stdout, err=False, nl=False)
        if result.stderr:
            typer.echo(result.stderr, err=True, nl=False)
        raise typer.Exit(code=result.return_code)
    except (PolicyViolationError, ExecutionPreparationError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except SecretNotFound as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
