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
