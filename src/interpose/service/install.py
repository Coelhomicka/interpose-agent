"""Install and remove the Windows service.

``interpose setup`` runs once, elevated (one UAC prompt), and then never needs
administrator rights again. What it sets up, and why:

1. A private copy of the Python runtime and of this package under
   ``%ProgramFiles%\\Interpose``. The interpreter a user installs lives in their
   profile and is writable by anything running as them; a service that loaded
   code from there could be patched by an agent into handing over the key.
2. The ``Interpose`` service, running as the virtual account
   ``NT SERVICE\\Interpose``: no password, no login, and an identity of its own.
   Its token keeps only ``SeChangeNotifyPrivilege``.
3. ``%ProgramData%\\Interpose\\vault`` for the database and master key, open to
   the service, SYSTEM and administrators only; and ``...\\client`` where the
   service publishes its endpoint and control token for the installing user.
4. The user's existing development vault is moved into the protected folder,
   and the copy in the user profile is destroyed (the key first overwritten).

Run it yourself, not from inside an agent session: until the service exists,
everything it installs from is still writable by that agent.
"""

from __future__ import annotations

import ctypes
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..core.elevation import is_elevated
from . import SERVICE_ACCOUNT, SERVICE_DISPLAY_NAME, SERVICE_NAME
from .layout import ServiceLayout

Log = Callable[[str], None]

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
USER_VAULT_FILES = ("runtime.db", "audit.db", "master.key")
SQLITE_SIDE_FILES = ("-wal", "-shm", "-journal")
ERROR_CANCELLED = 1223


class InstallError(RuntimeError):
    pass


# --------------------------------------------------------------------------- elevation


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def run_elevated(arguments: list[str]) -> int:
    """Run ``python -I <arguments>`` through a UAC prompt and wait for it."""
    see_mask_nocloseprocess = 0x40
    sw_hide = 0
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = see_mask_nocloseprocess
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = subprocess.list2cmdline(["-I", *arguments])
    info.lpDirectory = str(Path.cwd())
    info.nShow = sw_hide
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == ERROR_CANCELLED:
            raise InstallError("the administrator prompt was cancelled")
        raise ctypes.WinError(error)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(info.hProcess)
    return int(code.value)


# --------------------------------------------------------------------------- helpers


def _run(command: list[str], log: Log, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise InstallError(f"{' '.join(command[:3])} failed ({result.returncode}): {detail}")
    return result


def default_source() -> str:
    """What to ``pip install`` into the service runtime: the same code the user runs."""
    distribution = importlib.metadata.distribution("interpose")
    direct = distribution.read_text("direct_url.json")
    if direct:
        info = json.loads(direct)
        url = info.get("url", "")
        vcs = info.get("vcs_info")
        if vcs:
            # Installed straight from a repository (`pipx install git+https://...`):
            # pin the service to the exact commit the user installed.
            return f"{vcs.get('vcs', 'git')}+{url}@{vcs['commit_id']}"
        if info.get("archive_info") is not None and not url.startswith("file:"):
            return url
        if url.startswith("file:"):
            path = unquote(urlsplit(url).path)
            if len(path) > 2 and path[0] == "/" and path[2] == ":":
                path = path[1:]
            return str(Path(path))
    return f"interpose=={distribution.version}"


def _owner_sid(path: Path) -> str:
    """Owner of ``path`` as a SID string, or "" if it cannot be read."""
    se_file_object = 1
    owner_security_information = 0x1
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    if advapi32.GetNamedSecurityInfoW(str(path), se_file_object, owner_security_information, ctypes.byref(owner),
                                      None, None, None, ctypes.byref(descriptor)) != 0:
        return ""
    try:
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(owner, ctypes.byref(text)):
            return ""
        try:
            return text.value or ""
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


def _is_reparse_point(path: Path) -> bool:
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except (OSError, AttributeError):
        return False


def _assert_trusted_tree(root: Path) -> None:
    """Refuse a data folder someone else could have prepared.

    ``%ProgramData%`` lets ordinary users create folders, so before the first
    install an agent could plant ``Interpose\\vault\\master.key`` with a key it
    knows, or make ``vault`` a junction into its own profile. A folder we created
    is owned by Administrators or SYSTEM and contains no reparse points.
    """
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            if _is_reparse_point(Path(current) / name):
                raise InstallError(f"refusing to use {root}: {Path(current) / name} is a link or junction")
    if _is_reparse_point(root):
        raise InstallError(f"refusing to use {root}: it is a link or junction")
    owner = _owner_sid(root)
    if owner not in {ADMINISTRATORS_SID, SYSTEM_SID}:
        raise InstallError(
            f"refusing to use {root}: it is owned by {owner or 'an unknown account'}, not by Administrators. "
            "Something created it before Interpose was installed; inspect and remove it, then run setup again."
        )


def _service_exists() -> bool:
    from .win32 import service_status

    return service_status(SERVICE_NAME) is not None


def _wait_for(condition: Callable[[], bool], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.25)
    return condition()


def _wait_for_process_exit(pid: int, seconds: float) -> bool:
    synchronize = 0x00100000
    wait_timeout = 0x102
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        return True  # already gone
    try:
        return kernel32.WaitForSingleObject(handle, int(seconds * 1000)) != wait_timeout
    finally:
        kernel32.CloseHandle(handle)


def _remove_tree(path: Path, log: Log) -> None:
    """Remove ``path``, retrying while a just-stopped process releases its files."""
    def clear_read_only(function, name, _error) -> None:
        os.chmod(name, 0o700)
        function(name)

    for attempt in range(10):
        try:
            shutil.rmtree(path, onexc=clear_read_only)
            return
        except PermissionError:
            if attempt == 9:
                raise
            if attempt == 0:
                log(f"Waiting for files in {path} to be released ...")
            time.sleep(1)


def _stop_service(log: Log) -> None:
    from .win32 import service_status

    stopped = 1  # SERVICE_STOPPED
    status = service_status(SERVICE_NAME)
    if status is None or status[0] == stopped:
        return
    log("Stopping the running service...")
    _run(["sc", "stop", SERVICE_NAME], log, check=False)
    if not _wait_for(lambda: (service_status(SERVICE_NAME) or (stopped, 0))[0] == stopped, 30):
        raise InstallError("the service did not stop within 30 seconds")
    # The service reports "stopped" a moment before its process exits and unloads
    # the runtime's DLLs; replacing the runtime before then fails with access denied.
    if status[1] and not _wait_for_process_exit(status[1], 30):
        raise InstallError(f"the service process {status[1]} did not exit within 30 seconds")


# --------------------------------------------------------------------------- steps


def install_runtime(layout: ServiceLayout, source: str, log: Log) -> None:
    base = Path(sys.base_prefix)
    log(f"Copying the Python runtime from {base} to {layout.python_dir} ...")
    if layout.program_dir.exists():
        _remove_tree(layout.program_dir, log)

    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = {"__pycache__", "Scripts", "Doc"} & set(names)
        if Path(directory) == base / "Lib":
            skipped |= {"site-packages", "test", "idlelib", "turtledemo"} & set(names)
        return skipped

    shutil.copytree(base, layout.python_dir, ignore=ignore)
    (layout.python_dir / "Lib" / "site-packages").mkdir(exist_ok=True)
    python = str(layout.python_exe)
    log("Installing pip into the service runtime ...")
    _run([python, "-I", "-m", "ensurepip", "--default-pip"], log)
    log(f"Installing Interpose from {source} (this downloads dependencies) ...")
    _run([python, "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-warn-script-location",
          "--no-cache-dir", source], log)
    _run([python, "-I", "-c", "import interpose.service.host"], log)


def create_service(layout: ServiceLayout, log: Log) -> None:
    if _service_exists():
        _stop_service(log)
        log("Removing the previous service registration ...")
        _run(["sc", "delete", SERVICE_NAME], log)
        _wait_for(lambda: not _service_exists(), 15)
    command = subprocess.list2cmdline([str(layout.python_exe), "-I", "-m", "interpose.service.host"])
    log(f"Registering the service as {SERVICE_ACCOUNT} ...")
    _run(["sc", "create", SERVICE_NAME, "binPath=", command, "start=", "auto", "obj=", SERVICE_ACCOUNT,
          "DisplayName=", SERVICE_DISPLAY_NAME], log)
    _run(["sc", "description", SERVICE_NAME,
          "Holds Interpose secrets and injects them into approved requests from AI agents."], log)
    _run(["sc", "sidtype", SERVICE_NAME, "unrestricted"], log)
    _run(["sc", "privs", SERVICE_NAME, "SeChangeNotifyPrivilege"], log)
    _run(["sc", "failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000"],
         log)


def _icacls(path: Path, *arguments: str, log: Log, check: bool = True) -> None:
    _run(["icacls", str(path), *arguments, "/C", "/Q"], log, check=check)


def prepare_data(layout: ServiceLayout, user_sid: str, log: Log) -> None:
    if layout.data_dir.exists():
        _assert_trusted_tree(layout.data_dir)
    log(f"Locking down {layout.data_dir} ...")
    layout.vault_dir.mkdir(parents=True, exist_ok=True)
    layout.client_dir.mkdir(parents=True, exist_ok=True)
    full = f"*{SYSTEM_SID}:(OI)(CI)F", f"*{ADMINISTRATORS_SID}:(OI)(CI)F"
    service = f"{SERVICE_ACCOUNT}:(OI)(CI)"
    _icacls(layout.data_dir, "/setowner", f"*{ADMINISTRATORS_SID}", "/T", log=log)
    _icacls(layout.data_dir, "/inheritance:r", "/grant:r", *full, f"{service}RX", log=log)
    _icacls(layout.vault_dir, "/inheritance:r", "/grant:r", *full, f"{service}M", log=log)
    _icacls(layout.client_dir, "/inheritance:r", "/grant:r", *full, f"{service}M", f"*{user_sid}:(OI)(CI)RX",
            log=log)
    # Files inside take the folder's ACL; anything explicit on them is dropped.
    for folder in (layout.vault_dir, layout.client_dir):
        if any(folder.iterdir()):
            _icacls(folder / "*", "/reset", "/T", log=log, check=False)


def _destroy(path: Path) -> None:
    if path.name == "master.key":
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.write(os.urandom(max(size, 32)))
            handle.flush()
            os.fsync(handle.fileno())
    path.unlink()


def migrate_user_vault(layout: ServiceLayout, user_home: Path, *, keep: bool, log: Log) -> None:
    source = user_home / ".interpose"
    if not (source / "master.key").is_file():
        log("No development vault to migrate.")
        return
    if (layout.vault_dir / "master.key").exists():
        log(f"The service already has a vault; leaving {source} untouched.")
        return
    log(f"Moving the vault from {source} into {layout.vault_dir} ...")
    copied: list[Path] = []
    for name in USER_VAULT_FILES:
        for suffix in ("", *SQLITE_SIDE_FILES) if name.endswith(".db") else ("",):
            candidate = source / f"{name}{suffix}"
            if candidate.is_file():
                shutil.copyfile(candidate, layout.vault_dir / candidate.name)
                copied.append(candidate)
    _icacls(layout.vault_dir / "*", "/reset", "/T", log=log, check=False)
    if keep:
        log(f"Kept the original files in {source} (--keep-user-vault). Delete them yourself.")
        return
    for path in copied:
        _destroy(path)
    log(f"Destroyed the copy in {source}.")


def start_service(layout: ServiceLayout, log: Log) -> None:
    log("Starting the service ...")
    _run(["sc", "start", SERVICE_NAME], log)
    if not _wait_for(layout.endpoint_file.is_file, 30):
        raise InstallError(f"the service did not come up; see {layout.log_file}")


def install(
    layout: ServiceLayout,
    *,
    user_sid: str,
    user_home: Path,
    source: str,
    keep_user_vault: bool,
    log: Log,
) -> None:
    if not is_elevated():
        raise InstallError("installation must run elevated")
    if layout.data_dir.exists():
        _assert_trusted_tree(layout.data_dir)
    if _service_exists():
        _stop_service(log)
    install_runtime(layout, source, log)
    create_service(layout, log)
    prepare_data(layout, user_sid, log)
    migrate_user_vault(layout, user_home, keep=keep_user_vault, log=log)
    start_service(layout, log)
    marker = layout.data_dir / "installed.json"
    marker.write_text(json.dumps({"user_sid": user_sid, "source": source, "at": time.time()}), encoding="utf-8")
    log("Interpose service installed.")


def uninstall(layout: ServiceLayout, *, purge: bool, log: Log) -> None:
    if not is_elevated():
        raise InstallError("removal must run elevated")
    if _service_exists():
        _stop_service(log)
        _run(["sc", "delete", SERVICE_NAME], log)
        log("Service removed.")
    if layout.program_dir.exists():
        _remove_tree(layout.program_dir, log)
        log(f"Removed {layout.program_dir}.")
    if purge and layout.data_dir.exists():
        key = layout.vault_dir / "master.key"
        if key.exists():
            _destroy(key)
        shutil.rmtree(layout.data_dir)
        log(f"Removed {layout.data_dir} (vault destroyed).")
    elif layout.data_dir.exists():
        log(f"Kept the vault in {layout.vault_dir}; `interpose setup` will reuse it.")
