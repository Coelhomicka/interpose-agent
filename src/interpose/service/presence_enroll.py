"""Enroll the operator's authenticator (Windows Hello) for policy approvals.

Runs elevated, from the service's private runtime in ``%ProgramFiles%``, and
writes the credential's public key into the vault folder. Both locations are
closed to the user's processes, so code running as the user can neither enroll a
key of its own nor alter this program.

It calls the Windows WebAuthn API (``webauthn.dll``) directly, with the relying
party ``localhost``, the same one the dashboard's browser approval uses. No
attestation is requested: trust in the key comes from where it is written.

    python -I -m interpose.service.presence_enroll --out <presence.json>
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import os
import secrets
import sys
from ctypes import wintypes
from pathlib import Path

from ..core.presence import RP_ID, PresenceCredential, PresenceError, b64url_encode

_COSE_ES256 = -7
_COSE_RS256 = -257
_ATTACHMENT_ANY = 0
_USER_VERIFICATION_REQUIRED = 1
_ATTESTATION_NONE = 1


class _RpEntity(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszId", wintypes.LPCWSTR),
        ("pwszName", wintypes.LPCWSTR),
        ("pwszIcon", wintypes.LPCWSTR),
    ]


class _UserEntity(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("cbId", wintypes.DWORD),
        ("pbId", ctypes.POINTER(ctypes.c_ubyte)),
        ("pwszName", wintypes.LPCWSTR),
        ("pwszIcon", wintypes.LPCWSTR),
        ("pwszDisplayName", wintypes.LPCWSTR),
    ]


class _CoseParameter(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszCredentialType", wintypes.LPCWSTR),
        ("lAlg", wintypes.LONG),
    ]


class _CoseParameters(ctypes.Structure):
    _fields_ = [
        ("cCredentialParameters", wintypes.DWORD),
        ("pCredentialParameters", ctypes.POINTER(_CoseParameter)),
    ]


class _ClientData(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("cbClientDataJSON", wintypes.DWORD),
        ("pbClientDataJSON", ctypes.POINTER(ctypes.c_ubyte)),
        ("pwszHashAlgId", wintypes.LPCWSTR),
    ]


class _Credentials(ctypes.Structure):
    _fields_ = [("cCredentials", wintypes.DWORD), ("pCredentials", ctypes.c_void_p)]


class _Extensions(ctypes.Structure):
    _fields_ = [("cExtensions", wintypes.DWORD), ("pExtensions", ctypes.c_void_p)]


class _MakeCredentialOptions(ctypes.Structure):
    # WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, version 1 fields only.
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("dwTimeoutMilliseconds", wintypes.DWORD),
        ("CredentialList", _Credentials),
        ("Extensions", _Extensions),
        ("dwAuthenticatorAttachment", wintypes.DWORD),
        ("bRequireResidentKey", wintypes.BOOL),
        ("dwUserVerificationRequirement", wintypes.DWORD),
        ("dwAttestationConveyancePreference", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
    ]


class _CredentialAttestation(ctypes.Structure):
    # Leading fields of WEBAUTHN_CREDENTIAL_ATTESTATION; only these are read.
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszFormatType", wintypes.LPCWSTR),
        ("cbAuthenticatorData", wintypes.DWORD),
        ("pbAuthenticatorData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _bytes_pointer(data: bytes):
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return buffer, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))


def make_credential(*, label: str, timeout_ms: int = 120_000) -> bytes:
    """Ask Windows to create a credential for ``localhost``; returns its authenticator data."""
    webauthn = ctypes.WinDLL("webauthn.dll")
    user32 = ctypes.WinDLL("user32")
    kernel32 = ctypes.WinDLL("kernel32")

    rp = _RpEntity(1, RP_ID, "Interpose", None)
    user_id = secrets.token_bytes(16)
    user_buffer, user_pointer = _bytes_pointer(user_id)
    user = _UserEntity(1, len(user_id), user_pointer, label, None, label)
    algorithms = (_CoseParameter * 2)(
        _CoseParameter(1, "public-key", _COSE_RS256), _CoseParameter(1, "public-key", _COSE_ES256)
    )
    parameters = _CoseParameters(2, algorithms)
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64url_encode(secrets.token_bytes(32)),
            "origin": f"http://{RP_ID}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    client_buffer, client_pointer = _bytes_pointer(client_data_json)
    client_data = _ClientData(1, len(client_data_json), client_pointer, "SHA-256")
    options = _MakeCredentialOptions(
        1, timeout_ms, _Credentials(0, None), _Extensions(0, None),
        _ATTACHMENT_ANY, False, _USER_VERIFICATION_REQUIRED, _ATTESTATION_NONE, 0,
    )

    webauthn.WebAuthNAuthenticatorMakeCredential.restype = ctypes.c_long
    webauthn.WebAuthNAuthenticatorMakeCredential.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(_RpEntity),
        ctypes.POINTER(_UserEntity),
        ctypes.POINTER(_CoseParameters),
        ctypes.POINTER(_ClientData),
        ctypes.POINTER(_MakeCredentialOptions),
        ctypes.POINTER(ctypes.POINTER(_CredentialAttestation)),
    ]
    webauthn.WebAuthNGetErrorName.restype = wintypes.LPCWSTR
    webauthn.WebAuthNGetErrorName.argtypes = [ctypes.c_long]
    webauthn.WebAuthNFreeCredentialAttestation.argtypes = [ctypes.POINTER(_CredentialAttestation)]

    window = user32.GetForegroundWindow() or kernel32.GetConsoleWindow()
    attestation = ctypes.POINTER(_CredentialAttestation)()
    result = webauthn.WebAuthNAuthenticatorMakeCredential(
        window, ctypes.byref(rp), ctypes.byref(user), ctypes.byref(parameters),
        ctypes.byref(client_data), ctypes.byref(options), ctypes.byref(attestation),
    )
    del user_buffer, client_buffer  # kept alive until the call returned
    if result != 0:
        raise PresenceError(f"Windows did not create the credential: {webauthn.WebAuthNGetErrorName(result)}")
    try:
        value = attestation.contents
        return ctypes.string_at(value.pbAuthenticatorData, value.cbAuthenticatorData)
    finally:
        webauthn.WebAuthNFreeCredentialAttestation(attestation)


def enroll(out: Path) -> PresenceCredential:
    label = f"Interpose ({getpass.getuser()} on {os.environ.get('COMPUTERNAME', 'this PC')})"
    credential = PresenceCredential.from_registration(make_credential(label=label), label=label)
    out.parent.mkdir(parents=True, exist_ok=True)
    temporary = out.with_suffix(".tmp")
    temporary.write_text(credential.to_json(), encoding="utf-8")
    os.replace(temporary, out)
    return credential


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        credential = enroll(args.out)
    except (PresenceError, OSError) as exc:
        print(f"Windows Hello enrollment failed: {exc}", file=sys.stderr)
        return 1
    fingerprint = hashlib.sha256(credential.public_key_cose).hexdigest()[:16]
    print(f"Windows Hello enrolled for policy approvals (key {fingerprint}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
