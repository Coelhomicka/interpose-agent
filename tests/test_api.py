from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from interpose.api.app import create_app

TOKEN = "test-admin-token"
POLICY = "secret: github/prod\nallow:\n  hosts:\n    - evil.example\n"


@pytest.fixture()
def api(runtime_container):
    return TestClient(create_app(runtime_container, admin_token=TOKEN), base_url="http://127.0.0.1:8000")


def test_health_needs_no_token(api):
    assert api.get("/health").status_code == 200


def test_policy_creation_requires_token(api, runtime_container):
    # Without auth, any local process could grant itself a destination.
    response = api.post("/policies", json={"definition": POLICY})

    assert response.status_code == 401
    assert runtime_container.policy_repository.list() == []


def test_wrong_token_is_rejected(api):
    response = api.get("/secrets", headers={"Authorization": "Bearer nope"})

    assert response.status_code == 401


def test_valid_token_is_accepted(api):
    response = api.post(
        "/policies",
        json={"definition": POLICY},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 201


def test_browser_request_is_rejected_even_with_token(api):
    response = api.get(
        "/secrets",
        headers={"Authorization": f"Bearer {TOKEN}", "Origin": "https://evil.example"},
    )

    assert response.status_code == 403


def test_rebound_host_is_rejected(runtime_container):
    client = TestClient(create_app(runtime_container, admin_token=TOKEN), base_url="http://rebind.evil.example:8000")

    response = client.get("/secrets", headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 403


def test_openapi_schema_is_not_served(api):
    assert api.get("/openapi.json").status_code in {401, 404}
