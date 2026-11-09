"""Locale-independent Windows queries: which process runs a service, which owns a port.

``sc`` and ``netstat`` print localized text (``ESCUTANDO`` instead of
``LISTENING`` on a Portuguese install), so these use the Win32 APIs directly.
"""

from __future__ import annotations

import ctypes
import socket
import struct
from ctypes import wintypes

from . import SERVICE_NAME

SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_CONTROL_STOP = 0x00000001
ERROR_ACCESS_DENIED = 5
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_NOT_ACTIVE = 1062
SC_STATUS_PROCESS_INFO = 0
SERVICE_RUNNING = 4
AF_INET = 2
TCP_TABLE_OWNER_PID_LISTENER = 3
ERROR_INSUFFICIENT_BUFFER = 122


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


def service_status(name: str = SERVICE_NAME) -> tuple[int, int] | None:
    """``(state, pid)`` of a service, or None if it does not exist."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]

    manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not manager:
        return None
    try:
        service = advapi32.OpenServiceW(manager, name, SERVICE_QUERY_STATUS)
        if not service:
            return None
        try:
            status = SERVICE_STATUS_PROCESS()
            needed = wintypes.DWORD()
            if not advapi32.QueryServiceStatusEx(
                service, SC_STATUS_PROCESS_INFO, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)
            ):
                return None
            return int(status.dwCurrentState), int(status.dwProcessId)
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(manager)


def _control(name: str, *, start: bool) -> None:
    """Start or stop a service with the caller's own rights.

    ``interpose setup`` grants the installing user exactly these two rights on the
    Interpose service, so this needs no elevation. Raises PermissionError when the
    rights are missing (an install from before on-demand start).
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    advapi32.StartServiceW.restype = wintypes.BOOL
    advapi32.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    advapi32.ControlService.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]

    manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        service = advapi32.OpenServiceW(manager, name, SERVICE_START if start else SERVICE_STOP)
        if not service:
            error = ctypes.get_last_error()
            if error == ERROR_ACCESS_DENIED:
                raise PermissionError(f"this account may not {'start' if start else 'stop'} the {name} service")
            raise ctypes.WinError(error)
        try:
            if start:
                ok = advapi32.StartServiceW(service, 0, None)
                ignorable = ERROR_SERVICE_ALREADY_RUNNING
            else:
                status = (ctypes.c_byte * 64)()
                ok = advapi32.ControlService(service, SERVICE_CONTROL_STOP, status)
                ignorable = ERROR_SERVICE_NOT_ACTIVE
            if not ok:
                error = ctypes.get_last_error()
                if error != ignorable:
                    raise ctypes.WinError(error)
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(manager)


def start_service(name: str = SERVICE_NAME) -> None:
    _control(name, start=True)


def stop_service(name: str = SERVICE_NAME) -> None:
    _control(name, start=False)


def service_pid(name: str = SERVICE_NAME) -> int | None:
    status = service_status(name)
    if status is None or status[0] != SERVICE_RUNNING or status[1] == 0:
        return None
    return status[1]


def listener_pid(port: int) -> int | None:
    """PID of the process listening on IPv4 ``port`` on loopback or all interfaces."""
    iphlpapi = ctypes.WinDLL("iphlpapi")
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)
    buffer = ctypes.create_string_buffer(size.value)
    result = iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)
    if result != 0:
        return None
    (count,) = struct.unpack_from("<I", buffer, 0)
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    for index in range(count):
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buffer, 4 + index * row_size)
        row_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        address = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
        if row_port == port and address in {"127.0.0.1", "0.0.0.0"}:  # noqa: S104 - matching, not binding
            return int(row.dwOwningPid)
    return None
