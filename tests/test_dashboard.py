from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from interpose.container import create_container
from interpose.dashboard.app import CSRF_HEADER, DashboardAuth, DashboardContext, create_dashboard_app

DASHBOARD = "http://127.0.0.1:18888"
SECRET_VALUE = "sk-live-dashboard-test-value"


@pytest.fixture()
def setup(runtime_config, tmp_path):
    workdir = tmp_path / "my-app"
    workdir.mkdir()
    container = create_container(runtime_config, project_root=workdir)
    auth = DashboardAuth()
    app = create_dashboard_app(container, DashboardContext(workdir, "http://127.0.0.1:9876"), auth)
    return container, auth, TestClient(app, base_url=DASHBOARD)


def login(client, auth) -> str:
    response = client.get(f"/login?t={auth.login_token}", follow_redirects=False)
    assert response.status_code == 303
    return client.get("/api/session").json()["csrf"]


def test_requires_login(setup):
    _, _, client = setup

    assert client.get("/").status_code == 401
    assert client.get("/api/state").status_code == 401


def test_login_token_is_single_use(setup):
    _, auth, client = setup
    login(client, auth)

    replay = TestClient(client.app, base_url=DASHBOARD)
    response = replay.get(f"/login?t={auth.login_token}", follow_redirects=False)

    assert response.status_code == 401


def test_wrong_login_token_is_rejected(setup):
    _, _, client = setup

    assert client.get("/login?t=guess", follow_redirects=False).status_code == 401


def test_session_cookie_is_httponly_and_strict(setup):
    _, auth, client = setup

    response = client.get(f"/login?t={auth.login_token}", follow_redirects=False)

    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_mutation_requires_csrf_header(setup):
    _, auth, client = setup
    login(client, auth)

    response = client.post("/api/secrets", json={"scope": "global", "reference": "openai/prod", "value": "x"})

    assert response.status_code == 403


def test_cross_origin_request_is_rejected(setup):
    _, auth, client = setup
    csrf = login(client, auth)

    response = client.post(
        "/api/secrets",
        json={"scope": "global", "reference": "openai/prod", "value": "x"},
        headers={CSRF_HEADER: csrf, "Origin": "https://evil.example"},
    )

    assert response.status_code == 403


def test_rebound_host_is_rejected(setup):
    _, auth, client = setup
    rebound = TestClient(client.app, base_url="http://rebind.evil.example:18888")

    assert rebound.get(f"/login?t={auth.login_token}", follow_redirects=False).status_code == 403


def test_security_headers_present(setup):
    _, auth, client = setup
    login(client, auth)

    headers = client.get("/").headers

    assert "script-src 'self'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_project_scope_needs_registration(setup):
    _, auth, client = setup
    csrf = login(client, auth)

    response = client.post(
        "/api/secrets",
        json={"scope": "project", "reference": "openai/prod", "value": SECRET_VALUE},
        headers={CSRF_HEADER: csrf},
    )

    assert response.status_code == 409


def test_full_flow_never_returns_the_value(setup):
    container, auth, client = setup
    csrf = login(client, auth)
    headers = {CSRF_HEADER: csrf}

    project = client.post("/api/project", json={}, headers=headers).json()
    assert project["id"] == "my-app"

    client.post("/api/secrets", json={"scope": "global", "reference": "openai/prod", "value": "global-value"},
                headers=headers)
    stored = client.post(
        "/api/secrets",
        json={"scope": "project", "reference": "OpenAI/prod", "value": SECRET_VALUE},
        headers=headers,
    )
    assert stored.status_code == 201
    policy = client.post(
        "/api/policies",
        json={"scope": "project", "secret": "openai/prod", "hosts": ["api.openai.com"], "methods": ["POST"],
              "inject": [{"kind": "header", "name": "Authorization"}]},
        headers=headers,
    )
    assert policy.status_code == 201, policy.text

    state = client.get("/api/state")
    audit = client.get("/api/audit")
    for response in (stored, policy, state, audit):
        assert SECRET_VALUE not in response.text
        assert "global-value" not in response.text

    body = state.json()
    assert body["project"]["name"] == "my-app"
    assert {(s["scope"], s["reference"]) for s in body["secrets"]} == {
        ("global", "secret://openai/prod"),
        ("project", "secret://openai/prod"),
    }
    assert body["effective"] == [
        {"reference": "secret://openai/prod", "secret_from": "project", "policy_from": "project", "ready": True}
    ]
    # The broker in the same process now resolves the project value.
    assert container.secret_store.resolve("secret://openai/prod").value == SECRET_VALUE
    actions = [entry["action"] for entry in audit.json()]
    assert "ADMIN_SECRET_SET" in actions and "ADMIN_POLICY_SET" in actions


def test_invalid_policy_is_reported(setup):
    _, auth, client = setup
    csrf = login(client, auth)

    response = client.post(
        "/api/policies",
        json={"scope": "global", "secret": "openai/prod", "hosts": ["api.openai.com"], "paths": ["no-slash"]},
        headers={CSRF_HEADER: csrf},
    )

    assert response.status_code == 422


def test_static_assets_are_served(setup):
    _, auth, client = setup
    login(client, auth)

    assert "boot()" in client.get("/app.js").text
    assert client.get("/app.css").status_code == 200


def test_dashboard_reports_trimmed_value(setup):
    _, auth, client = setup
    csrf = login(client, auth)

    response = client.post(
        "/api/secrets",
        json={"scope": "global", "reference": "demo/api", "value": " sk-demo-SEGREDO-123"},
        headers={CSRF_HEADER: csrf},
    )

    assert response.status_code == 201
    assert response.json()["trimmed"] is True


@pytest.fixture()
def nested(runtime_config, tmp_path):
    """A registered parent project and a dashboard opened in a folder inside it."""
    parent = tmp_path / "workspace"
    child = parent / "app"
    child.mkdir(parents=True)
    container = create_container(runtime_config, project_root=child)
    container.project_registry.register(parent, "workspace")
    auth = DashboardAuth()
    app = create_dashboard_app(container, DashboardContext(child, "http://127.0.0.1:9876"), auth)
    client = TestClient(app, base_url=DASHBOARD)
    csrf = login(client, auth)
    return container, client, {CSRF_HEADER: csrf}, child


def test_folder_inside_a_project_can_become_its_own_project(nested):
    _, client, headers, _ = nested

    before = client.get("/api/state").json()
    assert before["project"]["name"] == "workspace"
    assert before["project_inherited"] is True

    assert client.post("/api/project", json={}, headers=headers).status_code == 200

    after = client.get("/api/state").json()
    assert after["project"]["name"] == "app"
    assert after["project_inherited"] is False


def test_unregister_removes_the_project_and_only_its_scope(nested):
    container, client, headers, _ = nested
    client.post("/api/project", json={}, headers=headers)
    client.post("/api/secrets", json={"scope": "project", "reference": "demo/api", "value": "p"}, headers=headers)
    client.post("/api/secrets", json={"scope": "global", "reference": "demo/api", "value": "g"}, headers=headers)
    client.post("/api/policies", json={"scope": "project", "secret": "demo/api", "hosts": ["h"]}, headers=headers)

    response = client.delete("/api/project", headers=headers)

    assert response.json() == {"id": "app", "secrets": 1, "policies": 1}
    state = client.get("/api/state").json()
    assert state["project"]["name"] == "workspace"  # the parent applies again
    assert {(s["scope"], s["reference"]) for s in state["secrets"]} == {("global", "secret://demo/api")}
    assert container.project_registry.get("app") is None


def test_unregister_requires_csrf(nested):
    _, client, _, _ = nested

    assert client.delete("/api/project").status_code == 403


@pytest.mark.parametrize(
    ("path", "broad"),
    [
        ("C:\\", True),
        (r"C:\Users\Mickael Coelho", True),
        (r"C:\Users\Mickael Coelho\interpose-demo", False),
        (r"C:\code\my-app", False),
    ],
)
def test_home_folders_and_drive_roots_are_too_broad(path, broad):
    import os

    from interpose.projects import too_broad

    if os.name != "nt":
        pytest.skip("Windows paths")
    assert too_broad(path) is broad


def test_posix_home_folders_are_too_broad():
    from pathlib import PurePosixPath

    from interpose import projects

    for path, broad in [("/", True), ("/home/ana", True), ("/root", True), ("/home/ana/app", False)]:
        assert projects.too_broad(PurePosixPath(path)) is broad, path


def test_registering_a_home_folder_is_refused(runtime_config, tmp_path, monkeypatch):
    from interpose import projects

    container = create_container(runtime_config, project_root=tmp_path)
    monkeypatch.setattr(projects, "too_broad", lambda path: True)
    auth = DashboardAuth()
    app = create_dashboard_app(container, DashboardContext(tmp_path, "http://127.0.0.1:9876"), auth)
    client = TestClient(app, base_url=DASHBOARD)
    csrf = login(client, auth)

    response = client.post("/api/project", json={}, headers={CSRF_HEADER: csrf})

    assert response.status_code == 422
    assert "home folder" in response.json()["detail"]
