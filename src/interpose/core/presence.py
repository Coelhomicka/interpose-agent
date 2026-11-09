"""User presence for changes that widen what a secret can reach.

A process running as the user can do anything the user's files allow, including
opening a dashboard session. What it cannot do is produce a WebAuthn assertion
from the user's authenticator (Windows Hello, Touch ID, a security key) without
the user's face, finger or PIN. So policy changes that could send a secret
somewhere new must carry such an assertion, made over a challenge that is bound
to that exact change.

Trust in the authenticator comes from enrollment. The credential's public key is
written by an elevated process into the service's private folder, which the
user's processes cannot write, so code running as the user cannot swap in a key
of its own. See ``interpose.service.presence_enroll``.

This module verifies assertions with the ``cryptography`` package only. It
accepts attestation-free credentials: their authenticity is established by the
elevated enrollment, not by an attestation certificate.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

RP_ID = "localhost"
CHALLENGE_TTL_SECONDS = 120.0
_FLAG_USER_PRESENT = 0x01
_FLAG_USER_VERIFIED = 0x04
_FLAG_ATTESTED_DATA = 0x40


class PresenceError(ValueError):
    """An assertion or enrollment record that must not be trusted."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 16384:
        raise PresenceError("invalid base64url value")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise PresenceError("invalid base64url value") from exc


# --- Minimal CBOR (RFC 8949) ----------------------------------------------------
# Only what credential public keys and authenticator data use: integers, byte and
# text strings, arrays, maps, and simple values. Indefinite lengths, tags and
# floats are refused, and nesting is bounded.


def _cbor_item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > 8:
        raise PresenceError("CBOR nesting too deep")
    if offset >= len(data):
        raise PresenceError("truncated CBOR")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if info < 24:
        argument = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if offset + size > len(data):
            raise PresenceError("truncated CBOR")
        argument = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    else:
        raise PresenceError("unsupported CBOR encoding")

    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major in (2, 3):
        end = offset + argument
        if end > len(data):
            raise PresenceError("truncated CBOR")
        raw = data[offset:end]
        if major == 2:
            return bytes(raw), end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise PresenceError("invalid CBOR text") from exc
    if major == 4:
        if argument > 64:
            raise PresenceError("CBOR array too long")
        items = []
        for _ in range(argument):
            item, offset = _cbor_item(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        if argument > 64:
            raise PresenceError("CBOR map too long")
        mapping: dict[Any, Any] = {}
        for _ in range(argument):
            key, offset = _cbor_item(data, offset, depth + 1)
            if not isinstance(key, (int, str)) or key in mapping:
                raise PresenceError("invalid CBOR map key")
            value, offset = _cbor_item(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], offset
    raise PresenceError("unsupported CBOR item")


def cbor_decode_prefix(data: bytes) -> tuple[Any, int]:
    """Decode one CBOR item at the start of ``data``; returns it and its length."""
    return _cbor_item(data, 0, 0)


# --- Keys and authenticator data ------------------------------------------------


def public_key_from_cose(cose: bytes):
    key, used = cbor_decode_prefix(cose)
    if used != len(cose) or not isinstance(key, dict):
        raise PresenceError("invalid COSE key")
    kty, alg = key.get(1), key.get(3)
    if kty == 2 and alg == -7 and key.get(-1) == 1:  # EC2, ES256, P-256
        x, y = key.get(-2), key.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise PresenceError("invalid P-256 key")
        numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1())
        try:
            return numbers.public_key()
        except ValueError as exc:
            raise PresenceError("invalid P-256 key") from exc
    if kty == 3 and alg == -257:  # RSA, RS256 (Windows Hello)
        n, e = key.get(-1), key.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) < 256:
            raise PresenceError("invalid RSA key (2048 bits minimum)")
        return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    if kty == 1 and alg == -8 and key.get(-1) == 6:  # OKP, EdDSA, Ed25519
        x = key.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise PresenceError("invalid Ed25519 key")
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    raise PresenceError("unsupported credential algorithm")


def _verify_signature(public_key, signature: bytes, message: bytes) -> None:
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
        else:  # pragma: no cover - public_key_from_cose returns only these
            raise PresenceError("unsupported key type")
    except InvalidSignature as exc:
        raise PresenceError("signature does not verify") from exc


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None = None
    public_key_cose: bytes | None = None

    @classmethod
    def parse(cls, data: bytes) -> AuthenticatorData:
        if len(data) < 37:
            raise PresenceError("authenticator data too short")
        rp_id_hash, flags = data[:32], data[32]
        (sign_count,) = struct.unpack(">I", data[33:37])
        credential_id = public_key_cose = None
        if flags & _FLAG_ATTESTED_DATA:
            if len(data) < 55:
                raise PresenceError("attested credential data truncated")
            (length,) = struct.unpack(">H", data[53:55])
            start = 55 + length
            if length == 0 or length > 1023 or start > len(data):
                raise PresenceError("invalid credential id")
            credential_id = data[55:start]
            _, used = cbor_decode_prefix(data[start:])
            public_key_cose = data[start:start + used]
        return cls(rp_id_hash, flags, sign_count, credential_id, public_key_cose)


# --- Enrolled credential --------------------------------------------------------


@dataclass
class PresenceCredential:
    credential_id: bytes
    public_key_cose: bytes
    sign_count: int = 0
    rp_id: str = RP_ID
    label: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "rp_id": self.rp_id,
                "credential_id": b64url_encode(self.credential_id),
                "public_key_cose": b64url_encode(self.public_key_cose),
                "sign_count": self.sign_count,
                "label": self.label,
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> PresenceCredential:
        try:
            payload = json.loads(text)
            credential = cls(
                credential_id=b64url_decode(payload["credential_id"]),
                public_key_cose=b64url_decode(payload["public_key_cose"]),
                sign_count=int(payload.get("sign_count", 0)),
                rp_id=str(payload.get("rp_id", RP_ID)),
                label=str(payload.get("label", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PresenceError("invalid enrollment record") from exc
        public_key_from_cose(credential.public_key_cose)  # refuse a record we could never verify
        return credential

    @classmethod
    def from_registration(cls, authenticator_data: bytes, *, label: str = "") -> PresenceCredential:
        parsed = AuthenticatorData.parse(authenticator_data)
        if parsed.rp_id_hash != hashlib.sha256(RP_ID.encode()).digest():
            raise PresenceError("credential was made for another relying party")
        if not parsed.flags & _FLAG_USER_VERIFIED:
            raise PresenceError("the authenticator did not verify the user")
        if parsed.credential_id is None or parsed.public_key_cose is None:
            raise PresenceError("registration carries no credential")
        public_key_from_cose(parsed.public_key_cose)
        return cls(parsed.credential_id, parsed.public_key_cose, parsed.sign_count, RP_ID, label)


@dataclass
class _Pending:
    session: str
    digest: bytes
    expires: float


class PresenceVerifier:
    """Issues change-bound challenges and verifies the assertions that answer them.

    The enrollment record is re-read on every use, so re-enrolling takes effect
    without restarting the service. A missing record means user presence is not
    configured; callers decide whether that is acceptable.
    """

    def __init__(self, record_path: Path) -> None:
        self._record_path = record_path
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def credential(self) -> PresenceCredential | None:
        try:
            text = self._record_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        return PresenceCredential.from_json(text)

    def enrolled(self) -> bool:
        try:
            return self.credential() is not None
        except PresenceError:
            return True  # a damaged record must not silently disable the requirement

    def begin(self, session: str, digest: bytes) -> dict[str, Any]:
        credential = self.credential()
        if credential is None:
            raise PresenceError("user presence is not enrolled")
        challenge = secrets.token_bytes(32)
        now = time.monotonic()
        with self._lock:
            self._pending = {key: value for key, value in self._pending.items() if value.expires > now}
            self._pending[b64url_encode(challenge)] = _Pending(session, digest, now + CHALLENGE_TTL_SECONDS)
        return {
            "challenge": b64url_encode(challenge),
            "rpId": credential.rp_id,
            "allowCredentials": [{"type": "public-key", "id": b64url_encode(credential.credential_id)}],
            "userVerification": "required",
            "timeout": int(CHALLENGE_TTL_SECONDS * 1000),
        }

    def finish(self, session: str, digest: bytes, assertion: dict[str, Any], *, origin: str) -> None:
        """Verify ``assertion`` for the change ``digest``; raises PresenceError otherwise.

        The challenge is consumed whatever the outcome, so an assertion can be
        tried once.
        """
        challenge = assertion.get("challenge")
        with self._lock:
            pending = self._pending.pop(challenge, None) if isinstance(challenge, str) else None
        if pending is None or pending.expires <= time.monotonic():
            raise PresenceError("approval expired or already used; try again")
        if not hmac.compare_digest(pending.session, session) or not hmac.compare_digest(pending.digest, digest):
            raise PresenceError("approval does not match this change")

        credential = self.credential()
        if credential is None:
            raise PresenceError("user presence is not enrolled")
        if not hmac.compare_digest(b64url_decode(assertion.get("credential_id", "")), credential.credential_id):
            raise PresenceError("unknown credential")

        client_data_json = b64url_decode(assertion.get("client_data_json", ""))
        try:
            client_data = json.loads(client_data_json)
        except ValueError as exc:
            raise PresenceError("invalid client data") from exc
        if not isinstance(client_data, dict) or client_data.get("type") != "webauthn.get":
            raise PresenceError("client data is not an assertion")
        if not hmac.compare_digest(str(client_data.get("challenge", "")).encode(), challenge.encode()):
            raise PresenceError("client data answers another challenge")
        if client_data.get("origin") != origin:
            raise PresenceError("assertion was made for another origin")

        authenticator_data = b64url_decode(assertion.get("authenticator_data", ""))
        parsed = AuthenticatorData.parse(authenticator_data)
        if parsed.rp_id_hash != hashlib.sha256(credential.rp_id.encode()).digest():
            raise PresenceError("assertion was made for another relying party")
        if not parsed.flags & _FLAG_USER_PRESENT or not parsed.flags & _FLAG_USER_VERIFIED:
            raise PresenceError("the authenticator did not verify the user")

        message = authenticator_data + hashlib.sha256(client_data_json).digest()
        _verify_signature(public_key_from_cose(credential.public_key_cose), b64url_decode(
            assertion.get("signature", "")
        ), message)

        if parsed.sign_count or credential.sign_count:
            # A counter that does not move forward means a cloned authenticator.
            if parsed.sign_count <= credential.sign_count:
                raise PresenceError("authenticator counter did not advance")
            credential.sign_count = parsed.sign_count
            # The counter is a clone signal, not the trust anchor.
            with contextlib.suppress(OSError):
                self._record_path.write_text(credential.to_json(), encoding="utf-8")


def change_digest(scope: str, document_json: str) -> bytes:
    """What an approval is bound to: the scope and the exact policy being stored."""
    return hashlib.sha256(json.dumps([scope, json.loads(document_json)], sort_keys=True).encode()).digest()
