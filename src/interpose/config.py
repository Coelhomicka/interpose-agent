from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def _normalize_key_material(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _decode_key(value: str) -> bytes:
    candidate = value.strip()
    if not candidate:
        raise ValueError("INTERPOSE_MASTER_KEY cannot be empty")
    if all(ch in "0123456789abcdefABCDEF" for ch in candidate) and len(candidate) % 2 == 0:
        return bytes.fromhex(candidate)
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return candidate.encode("utf-8")


@dataclass(frozen=True)
class RuntimePaths:
    home: Path
    database: Path
    audit_database: Path
    master_key_file: Path

    @classmethod
    def from_env(cls) -> RuntimePaths:
        home = Path(os.getenv("INTERPOSE_HOME", str(Path.home() / ".interpose"))).expanduser()
        return cls(
            home=home,
            database=home / "runtime.db",
            audit_database=home / "audit.db",
            master_key_file=home / "master.key",
        )


@dataclass(frozen=True)
class RuntimeConfig:
    paths: RuntimePaths
    master_key: bytes
    agent_name: str = "unknown"

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        paths = RuntimePaths.from_env()
        agent_name = os.getenv("INTERPOSE_AGENT", "unknown").strip() or "unknown"
        master_key = load_master_key(paths.master_key_file)
        return cls(paths=paths, master_key=master_key, agent_name=agent_name)


def load_runtime_config() -> RuntimeConfig:
    return RuntimeConfig.from_env()


def load_master_key(master_key_file: Path) -> bytes:
    env_value = os.getenv("INTERPOSE_MASTER_KEY")
    if env_value:
        return _normalize_key_material(_decode_key(env_value))

    master_key_file.parent.mkdir(parents=True, exist_ok=True)
    if master_key_file.exists():
        return _normalize_key_material(master_key_file.read_bytes())

    generated = os.urandom(32)
    _write_private_file(master_key_file, generated)
    return _normalize_key_material(generated)


def _write_private_file(path: Path, content: bytes) -> None:
    """Create ``path`` readable by the current user only.

    This keeps other accounts and inherited ACLs out. It does not stop a process
    running as the same user, which is why the broker must eventually run under
    its own OS identity.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    if os.name == "nt":
        restrict_windows_acl(path)


def _current_user_sid() -> str:
    output = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    sid = output.rsplit(",", 1)[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        raise RuntimeError("could not determine the current user SID")
    return sid


def _set_single_ace_dacl(path: Path, sid: str) -> None:
    """Replace the whole DACL of ``path`` with one protected entry: full control for ``sid``.

    ``icacls /grant:r`` only replaces the grant for the named account; explicit
    entries a creating process already put on the file (an elevated token adds
    SYSTEM, Administrators and OWNER RIGHTS) survive it. Setting the DACL from a
    security descriptor leaves nothing else behind.
    """
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32")
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    se_file_object = 1
    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:P(A;;FA;;;{sid})", 1, ctypes.byref(descriptor), None
    ):
        raise OSError(ctypes.get_last_error(), "could not build the security descriptor")
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "could not read the security descriptor")
        result = advapi32.SetNamedSecurityInfoW(
            str(path), se_file_object, dacl_security_information | protected_dacl_security_information,
            None, None, dacl, None,
        )
        if result != 0:
            raise OSError(result, f"could not set permissions on {path}")
    finally:
        kernel32.LocalFree(descriptor)


def restrict_windows_acl(path: Path) -> None:
    """Make the current user the only account with any access to ``path``."""
    try:
        _set_single_ace_dacl(path, _current_user_sid())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"warning: could not restrict permissions on {path}: {exc}", file=sys.stderr)
