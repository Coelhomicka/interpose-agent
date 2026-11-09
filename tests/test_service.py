"""The OS-service mode: per-project routing in one broker, folder-bound dashboard
logins, the control routes clients use, and the install helpers that can run
without administrator rights."""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from interpose.container import create_container
from interpose.core.policies import PolicyDocument
from interpose.dashboard.app import CSRF_HEADER, DashboardAuth, DashboardContext, create_dashboard_app
from interpose.proxy.http_proxy import create_proxy_app
from interpose.service import install as installer
from interpose.service.client import ServiceClient
from interpose.service.host import publish_endpoint, run_host, withdraw_endpoint
from interpose.service.layout import ServiceEndpoint, ServiceLayout, service_installed
from interpose.session.launcher import SessionLaunchError, expand_proxy_placeholder
from test_proxy_hardening import _Upstream

BROKER = "http://127.0.0.1:9876"
DASHBOARD = "http://127.0.0.1:18888"
CONTROL = "control-token-for-tests"


def _policy(secret: str, host: str = "localhost:8001") -> PolicyDocument:
    return PolicyDocument.from_yaml(f"secret: {secret}\nallow:\n  hosts: [{host}]\nmethods: [GET]\n")


@pytest.fixture()
def service_runtime(runtime_config, tmp_path):
    """A broker with no active project, as the service runs, and two projects."""
    container = create_container(runtime_config)
    alpha_root, beta_root = tmp_path / "alpha", tmp_path / "beta"
    alpha_root.mkdir()
    beta_root.mkdir()
    alpha = container.project_registry.register(alpha_root, "alpha")
    beta = container.project_registry.register(beta_root, "beta")
    backend = container.secret_store.backend
    backend.store("secret://demo/api", "global-value", scope="global")
    backend.store("secret://demo/api", "alpha-value", scope=f"project:{alpha.id}")
    container.policy_repository.store(_policy("demo/api"), scope="global")
    return container, alpha, beta, alpha_root, beta_root


# --------------------------------------------------------------------------- proxy routing


def test_project_prefix_selects_that_projects_secret(service_runtime, monkeypatch):
    container, alpha, beta, *_ = service_runtime
    upstream = _Upstream()
    upstream.install(monkeypatch)
    client = TestClient(create_proxy_app(container), base_url=BROKER)
    headers = {"Authorization": "Bearer secret://demo/api"}

    assert client.get(f"/p/{alpha.id}/proxy/localhost:8001/v1/me", headers=headers).status_code == 200
    assert client.get(f"/p/{beta.id}/proxy/localhost:8001/v1/me", headers=headers).status_code == 200
    assert client.get("/proxy/localhost:8001/v1/me", headers=headers).status_code == 200

    sent = [call["headers"]["authorization"] for call in upstream.calls]
    assert sent == ["Bearer alpha-value", "Bearer global-value", "Bearer global-value"]


def test_unknown_project_prefix_is_rejected(service_runtime, monkeypatch):
    container, *_ = service_runtime
    upstream = _Upstream()
    upstream.install(monkeypatch)
    client = TestClient(create_proxy_app(container), base_url=BROKER)

    response = client.get("/p/nope/proxy/localhost:8001/v1/me", headers={"Authorization": "Bearer secret://demo/api"})

    assert response.status_code == 404
    assert upstream.calls == []


def test_project_policy_applies_under_prefix(service_runtime, monkeypatch):
    container, alpha, _, *_ = service_runtime
    # The project narrows the destination; the global policy must not leak through.
    container.policy_repository.store(_policy("demo/api", host="api.example.com"), scope=f"project:{alpha.id}")
    upstream = _Upstream()
    upstream.install(monkeypatch)
    client = TestClient(create_proxy_app(container), base_url=BROKER)

    response = client.get(f"/p/{alpha.id}/proxy/localhost:8001/v1/me",
                          headers={"Authorization": "Bearer secret://demo/api"})

    assert response.status_code == 403
    assert upstream.calls == []


def test_upstream_server_and_date_headers_are_not_duplicated(service_runtime, monkeypatch):
    container, *_ = service_runtime
    upstream = _Upstream(httpx.Response(200, json={}, headers={"server": "BaseHTTP/0.6", "date": "x"},
                                        request=httpx.Request("GET", "http://localhost:8001/")))
    upstream.install(monkeypatch)
    client = TestClient(create_proxy_app(container), base_url=BROKER)

    response = client.get("/proxy/localhost:8001/v1/me", headers={"Authorization": "Bearer secret://demo/api"})

    assert "BaseHTTP" not in response.headers.get("server", "")
    assert response.headers.get("date") != "x"


# --------------------------------------------------------------------------- dashboard


def _service_dashboard(container):
    auth = DashboardAuth(default_token=False)
    app = create_dashboard_app(
        container, DashboardContext(None, BROKER, follow_project=False), auth, control_token=CONTROL
    )
    return auth, app


def _control(app) -> TestClient:
    client = TestClient(app, base_url=DASHBOARD)
    client.headers["Authorization"] = f"Bearer {CONTROL}"
    return client


def _login(app, path: str) -> TestClient:
    browser = TestClient(app, base_url=DASHBOARD)
    assert browser.get(path, follow_redirects=False).status_code == 303
    return browser


def test_login_link_is_bound_to_its_folder(service_runtime):
    container, alpha, beta, alpha_root, beta_root = service_runtime
    _, app = _service_dashboard(container)
    control = _control(app)

    in_alpha = _login(app, control.post("/control/login", json={"cwd": str(alpha_root)}).json()["path"])
    in_beta = _login(app, control.post("/control/login", json={"cwd": str(beta_root)}).json()["path"])

    assert in_alpha.get("/api/state").json()["project"]["id"] == alpha.id
    assert in_beta.get("/api/state").json()["project"]["id"] == beta.id
    beta_secrets = {(s["scope"], s["reference"]) for s in in_beta.get("/api/state").json()["secrets"]}
    assert beta_secrets == {("global", "secret://demo/api")}


def test_session_writes_land_in_its_own_project(service_runtime):
    container, _, beta, _, beta_root = service_runtime
    _, app = _service_dashboard(container)
    browser = _login(app, _control(app).post("/control/login", json={"cwd": str(beta_root)}).json()["path"])
    csrf = browser.get("/api/session").json()["csrf"]

    response = browser.post("/api/secrets", json={"scope": "project", "reference": "demo/api", "value": "beta-value"},
                            headers={CSRF_HEADER: csrf})

    assert response.status_code == 201
    assert container.secret_store.backend.resolve(
        "secret://demo/api", scopes=(f"project:{beta.id}",)
    ).value == "beta-value"


def test_service_login_links_are_single_use(service_runtime):
    container, _, _, alpha_root, _ = service_runtime
    _, app = _service_dashboard(container)
    path = _control(app).post("/control/login", json={"cwd": str(alpha_root)}).json()["path"]
    _login(app, path)

    replay = TestClient(app, base_url=DASHBOARD)
    assert replay.get(path, follow_redirects=False).status_code == 401


def test_service_dashboard_has_no_default_login(service_runtime):
    container, *_ = service_runtime
    auth, app = _service_dashboard(container)

    assert auth.login_token == ""
    assert TestClient(app, base_url=DASHBOARD).get("/login?t=", follow_redirects=False).status_code == 401


def test_control_routes_require_the_token(service_runtime):
    container, *_ = service_runtime
    _, app = _service_dashboard(container)
    anonymous = TestClient(app, base_url=DASHBOARD)

    assert anonymous.post("/control/login", json={"cwd": "C:\\"}).status_code == 401
    wrong = anonymous.post("/control/login", json={"cwd": "C:\\"}, headers={"Authorization": "Bearer guess"})
    assert wrong.status_code == 401


@pytest.mark.parametrize("header", [{"Origin": DASHBOARD}, {"Sec-Fetch-Site": "same-origin"}])
def test_control_routes_refuse_browsers(service_runtime, header):
    container, *_ = service_runtime
    _, app = _service_dashboard(container)

    response = _control(app).post("/control/login", json={"cwd": "C:\\"}, headers=header)

    assert response.status_code == 403


def test_control_routes_absent_without_a_token(runtime_config, tmp_path):
    container = create_container(runtime_config, project_root=tmp_path)
    app = create_dashboard_app(container, DashboardContext(tmp_path, BROKER))
    client = TestClient(app, base_url=DASHBOARD)

    assert client.post("/control/login", json={"cwd": str(tmp_path)},
                       headers={"Authorization": "Bearer anything"}).status_code == 404


def test_control_rejects_relative_folders(service_runtime):
    container, *_ = service_runtime
    _, app = _service_dashboard(container)

    assert _control(app).post("/control/login", json={"cwd": "relative/dir"}).status_code == 422


def test_control_project_and_secret_lookup(service_runtime):
    container, alpha, _, alpha_root, beta_root = service_runtime
    _, app = _service_dashboard(container)
    control = _control(app)

    assert control.get("/control/project", params={"cwd": str(alpha_root / "src")}).json() == {"id": alpha.id}
    exists = control.get("/control/secret-exists", params={"reference": "demo/api", "cwd": str(beta_root)})
    assert exists.json() == {"exists": True}
    missing = control.get("/control/secret-exists", params={"reference": "demo/other", "cwd": str(beta_root)})
    assert missing.json() == {"exists": False}


# --------------------------------------------------------------------------- sessions


def test_proxy_placeholder_is_expanded():
    expanded = expand_proxy_placeholder(
        {"BASE": "${INTERPOSE_PROXY}/localhost:8001", "OTHER": "x"}, "http://127.0.0.1:9876/p/alpha/proxy/"
    )

    assert expanded == {"BASE": "http://127.0.0.1:9876/p/alpha/proxy/localhost:8001", "OTHER": "x"}


def test_proxy_placeholder_without_broker_fails():
    with pytest.raises(SessionLaunchError):
        expand_proxy_placeholder({"BASE": "${INTERPOSE_PROXY}/x"}, None)


# --------------------------------------------------------------------------- host and client


def test_service_mode_is_off_when_interpose_home_is_set(tmp_path, monkeypatch):
    layout = ServiceLayout(program_dir=tmp_path / "program", data_dir=tmp_path / "data")
    publish_endpoint(layout, ServiceEndpoint(BROKER, DASHBOARD, 1), CONTROL)

    monkeypatch.setenv("INTERPOSE_HOME", str(tmp_path / "dev"))
    assert service_installed(layout) is False
    monkeypatch.delenv("INTERPOSE_HOME")
    # The service exists only on Windows; elsewhere development mode is the only mode.
    assert service_installed(layout) is (os.name == "nt")

    withdraw_endpoint(layout)
    assert service_installed(layout) is False


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_host_serves_and_publishes_its_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERPOSE_HOME", str(tmp_path / "ignored"))  # restored after the host overrides it
    monkeypatch.delenv("INTERPOSE_MASTER_KEY", raising=False)
    layout = ServiceLayout(program_dir=tmp_path / "program", data_dir=tmp_path / "data")
    proxy_port, dashboard_port = _free_port(), _free_port()
    stop = threading.Event()
    thread = threading.Thread(
        target=run_host, args=(layout, stop), kwargs={"proxy_port": proxy_port, "dashboard_port": dashboard_port},
        daemon=True,
    )
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not layout.endpoint_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        client = ServiceClient.connect(layout)
        assert client.endpoint.proxy_url == f"http://127.0.0.1:{proxy_port}"
        assert (layout.vault_dir / "master.key").is_file()

        login_url = client.login_url(tmp_path)
        assert login_url.startswith(f"http://127.0.0.1:{dashboard_port}/login?t=")
        assert client.proxy_base(tmp_path) == f"http://127.0.0.1:{proxy_port}/proxy"
        assert client.secret_exists("demo/api", tmp_path) is False
    finally:
        stop.set()
        thread.join(timeout=15)
    assert not thread.is_alive()
    assert not layout.endpoint_file.exists()


# --------------------------------------------------------------------------- installer helpers


def test_default_source_is_the_local_checkout_for_editable_installs(monkeypatch):
    class FakeDistribution:
        version = "0.1.0"

        def read_text(self, name):
            return '{"dir_info": {"editable": true}, "url": "file:///C:/secret-runtime"}'

    monkeypatch.setattr(installer.importlib.metadata, "distribution", lambda name: FakeDistribution())

    assert installer.default_source() == str(Path("C:/secret-runtime"))


def test_default_source_is_the_released_version_otherwise(monkeypatch):
    class FakeDistribution:
        version = "1.2.3"

        def read_text(self, name):
            return None

    monkeypatch.setattr(installer.importlib.metadata, "distribution", lambda name: FakeDistribution())

    assert installer.default_source() == "interpose==1.2.3"


def test_migration_moves_the_vault_and_destroys_the_user_copy(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "_icacls", lambda *args, **kwargs: None)
    user_vault = tmp_path / "home" / ".interpose"
    user_vault.mkdir(parents=True)
    (user_vault / "master.key").write_bytes(b"k" * 32)
    (user_vault / "runtime.db").write_bytes(b"db")
    (user_vault / "audit.db").write_bytes(b"audit")
    layout = ServiceLayout(program_dir=tmp_path / "program", data_dir=tmp_path / "data")
    layout.vault_dir.mkdir(parents=True)

    installer.migrate_user_vault(layout, tmp_path / "home", keep=False, log=lambda message: None)

    assert (layout.vault_dir / "master.key").read_bytes() == b"k" * 32
    assert (layout.vault_dir / "runtime.db").read_bytes() == b"db"
    assert not any(user_vault.iterdir())


def test_migration_never_overwrites_an_existing_service_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "_icacls", lambda *args, **kwargs: None)
    user_vault = tmp_path / "home" / ".interpose"
    user_vault.mkdir(parents=True)
    (user_vault / "master.key").write_bytes(b"user-key")
    layout = ServiceLayout(program_dir=tmp_path / "program", data_dir=tmp_path / "data")
    layout.vault_dir.mkdir(parents=True)
    (layout.vault_dir / "master.key").write_bytes(b"service-key")

    installer.migrate_user_vault(layout, tmp_path / "home", keep=False, log=lambda message: None)

    assert (layout.vault_dir / "master.key").read_bytes() == b"service-key"
    assert (user_vault / "master.key").read_bytes() == b"user-key"


def test_untrusted_data_folder_is_refused(tmp_path, monkeypatch):
    planted = tmp_path / "Interpose"
    (planted / "vault").mkdir(parents=True)
    monkeypatch.setattr(installer, "_owner_sid", lambda path: "S-1-5-21-1-2-3-1001")

    with pytest.raises(installer.InstallError, match="owned by"):
        installer._assert_trusted_tree(planted)


def test_trusted_data_folder_is_accepted(tmp_path, monkeypatch):
    (tmp_path / "Interpose" / "vault").mkdir(parents=True)
    monkeypatch.setattr(installer, "_owner_sid", lambda path: installer.ADMINISTRATORS_SID)

    installer._assert_trusted_tree(tmp_path / "Interpose")


def test_default_source_pins_the_commit_of_a_git_install(monkeypatch):
    class FakeDistribution:
        version = "0.1.0"

        def read_text(self, name):
            return (
                '{"url": "https://github.com/Coelhomicka/interpose-agent.git", '
                '"vcs_info": {"vcs": "git", "commit_id": "8e56e15c26229dd87eb61491a24dfc421ded02c6"}}'
            )

    monkeypatch.setattr(installer.importlib.metadata, "distribution", lambda name: FakeDistribution())

    assert installer.default_source() == (
        "git+https://github.com/Coelhomicka/interpose-agent.git@8e56e15c26229dd87eb61491a24dfc421ded02c6"
    )
