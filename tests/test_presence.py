"""User presence (WebAuthn / Windows Hello) for policy changes that widen egress.

A software authenticator stands in for Windows Hello: it holds a real key pair and
produces real WebAuthn assertions, so the verifier is exercised end to end.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from interpose.container import create_container
from interpose.core.policies import PolicyDocument, widens
from interpose.core.presence import (
    RP_ID,
    AuthenticatorData,
    PresenceCredential,
    PresenceError,
    PresenceVerifier,
    b64url_decode,
    b64url_encode,
    cbor_decode_prefix,
)
from interpose.dashboard.app import CSRF_HEADER, DashboardAuth, DashboardContext, create_dashboard_app

DASHBOARD = "http://localhost:18888"


# --- a software authenticator ------------------------------------------------------


def _cbor(value) -> bytes:
    def head(major: int, argument: int) -> bytes:
        if argument < 24:
            return bytes([major << 5 | argument])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if argument < 1 << (8 * size):
                return bytes([major << 5 | info]) + argument.to_bytes(size, "big")
        raise ValueError(argument)

    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(_cbor(k) + _cbor(v) for k, v in value.items())
    raise TypeError(value)


class SoftAuthenticator:
    def __init__(self, kind: str = "ec") -> None:
        self.kind = kind
        self.credential_id = b"soft-credential-id-0001"
        self.counter = 0
        if kind == "ec":
            self.key = ec.generate_private_key(ec.SECP256R1())
            numbers = self.key.public_key().public_numbers()
            x, y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")
            self.cose = _cbor({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = self.key.public_key().public_numbers()
            self.cose = _cbor({1: 3, 3: -257, -1: numbers.n.to_bytes(256, "big"), -2: numbers.e.to_bytes(3, "big")})

    def registration(self, flags: int = 0x45) -> bytes:
        rp_hash = hashlib.sha256(RP_ID.encode()).digest()
        attested = bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose
        return rp_hash + bytes([flags]) + struct.pack(">I", 0) + attested

    def assert_(self, options: dict, *, origin: str = DASHBOARD, flags: int = 0x05, rp_id: str = RP_ID,
                kind: str = "webauthn.get", counter_step: int = 1) -> dict:
        self.counter += counter_step
        client_data = json.dumps({"type": kind, "challenge": options["challenge"], "origin": origin}).encode()
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        message = auth_data + hashlib.sha256(client_data).digest()
        if self.kind == "ec":
            signature = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        else:
            signature = self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return {
            "challenge": options["challenge"],
            "credential_id": b64url_encode(self.credential_id),
            "authenticator_data": b64url_encode(auth_data),
            "client_data_json": b64url_encode(client_data),
            "signature": b64url_encode(signature),
        }


def _enroll(path, authenticator: SoftAuthenticator) -> None:
    path.write_text(PresenceCredential.from_registration(authenticator.registration()).to_json(), encoding="utf-8")


# --- dashboard flow --------------------------------------------------------------


POLICY = {"scope": "global", "secret": "github/prod", "hosts": ["api.github.com"], "inject": [
    {"kind": "header", "name": "Authorization"}]}


@pytest.fixture()
def env(runtime_config, tmp_path):
    workdir = tmp_path / "app"
    workdir.mkdir()
    container = create_container(runtime_config, project_root=workdir)
    record = tmp_path / "presence.json"
    authenticator = SoftAuthenticator()
    _enroll(record, authenticator)
    auth = DashboardAuth()
    app = create_dashboard_app(
        container, DashboardContext(workdir, "http://127.0.0.1:9876"), auth, presence=PresenceVerifier(record)
    )
    client = TestClient(app, base_url=DASHBOARD)
    client.get(f"/login?t={auth.login_token}", follow_redirects=False)
    csrf = client.get("/api/session").json()["csrf"]
    client.headers[CSRF_HEADER] = csrf
    return container, client, authenticator, record


def _approve(client, authenticator, payload, **assertion_options):
    first = client.post("/api/policies", json=payload)
    assert first.status_code == 428, first.text
    approval = authenticator.assert_(first.json()["approval"], **assertion_options)
    return client.post("/api/policies", json={**payload, "approval": approval}), approval


def test_new_policy_requires_presence_and_succeeds_with_it(env):
    container, client, authenticator, _ = env

    response, _ = _approve(client, authenticator, POLICY)

    assert response.status_code == 201
    assert container.policy_repository.list()[0].secret_reference == "secret://github/prod"


def test_agent_with_a_session_but_no_authenticator_cannot_widen(env):
    container, client, _, _ = env

    first = client.post("/api/policies", json=POLICY)
    forged = {"challenge": first.json()["approval"]["challenge"], "credential_id": "AAAA",
              "authenticator_data": "AAAA", "client_data_json": "AAAA", "signature": "AAAA"}
    second = client.post("/api/policies", json={**POLICY, "approval": forged})

    assert second.status_code == 403
    assert container.policy_repository.list() == []


def test_approval_cannot_be_replayed(env):
    _, client, authenticator, _ = env
    _, approval = _approve(client, authenticator, POLICY)

    other = {**POLICY, "secret": "github/other"}
    replay = client.post("/api/policies", json={**other, "approval": approval})

    assert replay.status_code == 403


def test_approval_is_bound_to_the_exact_change(env):
    container, client, authenticator, _ = env
    first = client.post("/api/policies", json=POLICY)
    approval = authenticator.assert_(first.json()["approval"])

    swapped = {**POLICY, "hosts": ["attacker.test"]}
    response = client.post("/api/policies", json={**swapped, "approval": approval})

    assert response.status_code == 403
    assert container.policy_repository.list() == []


@pytest.mark.parametrize(
    "options",
    [
        {"flags": 0x01},  # present but not verified (no PIN or biometric)
        {"origin": "http://evil.localhost:18888"},
        {"rp_id": "evil.test"},
        {"kind": "webauthn.create"},
        {"counter_step": 0},  # cloned authenticator: counter did not move
    ],
)
def test_bad_assertions_are_refused(env, options):
    _, client, authenticator, _ = env
    authenticator.counter = 5 if options.get("counter_step") == 0 else 0
    if options.get("counter_step") == 0:
        record = env[3]
        credential = PresenceCredential.from_json(record.read_text())
        credential.sign_count = 5
        record.write_text(credential.to_json())

    response, _ = _approve(client, authenticator, POLICY, **options)

    assert response.status_code == 403


def test_narrowing_needs_no_approval(env):
    _, client, authenticator, _ = env
    _approve(client, authenticator, {**POLICY, "hosts": ["api.github.com", "uploads.github.com"]})

    narrower = client.post("/api/policies", json=POLICY)

    assert narrower.status_code == 201


def test_ip_host_is_sent_to_localhost(env):
    _, client, _, _ = env
    ip_client = TestClient(client.app, base_url="http://127.0.0.1:18888")
    ip_client.headers[CSRF_HEADER] = client.headers[CSRF_HEADER]
    ip_client.headers["Cookie"] = f"interpose_session={client.cookies.get('interpose_session')}"

    response = ip_client.post("/api/policies", json=POLICY)

    assert response.status_code == 409
    assert "localhost" in response.json()["detail"]


def test_not_enrolled_is_reported_and_allowed(env):
    _, client, _, record = env
    record.unlink()

    assert client.get("/api/state").json()["presence"] == "missing"
    assert client.post("/api/policies", json=POLICY).status_code == 201


def test_rsa_keys_as_used_by_windows_hello(tmp_path):
    authenticator = SoftAuthenticator("rsa")
    record = tmp_path / "presence.json"
    _enroll(record, authenticator)
    verifier = PresenceVerifier(record)
    digest = b"d" * 32

    options = verifier.begin("session", digest)
    verifier.finish("session", digest, authenticator.assert_(options), origin=DASHBOARD)


def test_damaged_record_keeps_presence_required(tmp_path):
    record = tmp_path / "presence.json"
    record.write_text("{not json")

    assert PresenceVerifier(record).enrolled() is True


def test_registration_without_user_verification_is_refused():
    with pytest.raises(PresenceError):
        PresenceCredential.from_registration(SoftAuthenticator().registration(flags=0x41))


# --- what counts as widening -----------------------------------------------------


def _doc(text: str) -> PolicyDocument:
    return PolicyDocument.from_yaml("secret: github/prod\n" + text)


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (None, "allow: {hosts: [api.github.com]}", True),
        ("allow: {hosts: [api.github.com]}", "allow: {hosts: [api.github.com]}", False),
        ("allow: {hosts: ['*.github.com']}", "allow: {hosts: [api.github.com]}", False),
        ("allow: {hosts: [api.github.com]}", "allow: {hosts: ['*.github.com']}", True),
        ("allow: {hosts: [api.github.com]}", "allow: {hosts: [attacker.test]}", True),
        ("allow: {hosts: [a.test]}\nmethods: [GET]", "allow: {hosts: [a.test]}", True),
        ("allow: {hosts: [a.test]}", "allow: {hosts: [a.test]}\nmethods: [GET]", False),
        ("allow: {hosts: [a.test]}\npaths: [/x]", "allow: {hosts: [a.test]}", True),
        ("allow: {hosts: [a.test]}", "allow: {hosts: [a.test]}\ninject: [{query: key}]", True),
        ("allow: {hosts: [a.test]}", "allow: {hosts: [a.test]}\nallow_exec: true", True),
        ("allow: {hosts: [a.test]}", "allow: {hosts: [a.test]}\nschemes: [https, http]", True),
        ("allow: {hosts: [a.test]}\ndeny: {hosts: [b.a.test]}", "allow: {hosts: [a.test]}", True),
    ],
)
def test_widening_rules(old, new, expected):
    assert widens(_doc(new), _doc(old) if old else None) is expected


# --- parser robustness -----------------------------------------------------------


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=300))
def test_fuzz_parsers_only_raise_presence_errors(data):
    for parse in (cbor_decode_prefix, AuthenticatorData.parse, lambda d: b64url_decode(d.decode("latin-1"))):
        with contextlib.suppress(PresenceError):
            parse(data)
