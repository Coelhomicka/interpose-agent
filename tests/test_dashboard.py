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
