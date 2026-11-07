"""Minimal Windows Service Control Manager glue in ctypes.

A process started by the SCM must call ``StartServiceCtrlDispatcherW`` and report
its state, or the SCM kills it after 30 seconds. pywin32 does this, but it is a
large native dependency with its own post-install step; the few calls needed are
small enough to bind directly, which keeps ``pip install interpose`` plug-and-play.
"""

from __future__ import annotations

import ctypes
import threading
from collections.abc import Callable
from ctypes import wintypes

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_ACCEPT_STOP = 0x1
SERVICE_ACCEPT_SHUTDOWN = 0x4
SERVICE_CONTROL_STOP = 0x1
SERVICE_CONTROL_INTERROGATE = 0x4
SERVICE_CONTROL_SHUTDOWN = 0x5
NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SERVICE_SPECIFIC_ERROR = 1066
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063


class NotStartedByServiceManager(RuntimeError):
    """The process was run from a console, not by the SCM."""


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


_SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
_HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", _SERVICE_MAIN)]


def _advapi32():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    library.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    library.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, _HANDLER_EX, wintypes.LPVOID]
    library.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    library.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
    library.SetServiceStatus.restype = wintypes.BOOL
    return library


def run_service(name: str, body: Callable[[threading.Event], None]) -> None:
    """Hand the process to the SCM and run ``body(stop_event)`` as the service.

    ``body`` must return soon after ``stop_event`` is set. Raises
    ``NotStartedByServiceManager`` when the process was not launched by the SCM.
    """
    advapi32 = _advapi32()
    stop_event = threading.Event()
    status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 0, NO_ERROR, 0, 0, 10_000)
    handle: list[int] = []

    def report(state: int, *, exit_code: int = NO_ERROR, wait_hint: int = 0) -> None:
        status.dwCurrentState = state
        status.dwControlsAccepted = 0 if state == SERVICE_START_PENDING else (
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        )
        if exit_code != NO_ERROR:
            status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR
            status.dwServiceSpecificExitCode = exit_code
        status.dwWaitHint = wait_hint
        status.dwCheckPoint = 0 if state in (SERVICE_RUNNING, SERVICE_STOPPED) else status.dwCheckPoint + 1
        if handle:
            advapi32.SetServiceStatus(handle[0], ctypes.byref(status))

    def handler(control: int, _event_type: int, _event_data: int, _context: int) -> int:
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            report(SERVICE_STOP_PENDING, wait_hint=15_000)
            stop_event.set()
            return NO_ERROR
        if control == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    handler_callback = _HANDLER_EX(handler)

    def service_main(_argc: int, _argv) -> None:
        registered = advapi32.RegisterServiceCtrlHandlerExW(name, handler_callback, None)
        if not registered:
            return
        handle.append(registered)
        report(SERVICE_START_PENDING, wait_hint=30_000)
        exit_code = NO_ERROR
        try:
            report(SERVICE_RUNNING)
            body(stop_event)
        except BaseException:
            # ctypes swallows exceptions raised in callbacks; the body logs its own
            # failures, and the SCM still has to hear that the service stopped.
            exit_code = 1
        finally:
            report(SERVICE_STOPPED, exit_code=exit_code)

    main_callback = _SERVICE_MAIN(service_main)
    table = (SERVICE_TABLE_ENTRYW * 2)(
        SERVICE_TABLE_ENTRYW(name, main_callback),
        SERVICE_TABLE_ENTRYW(None, _SERVICE_MAIN()),
    )
    if not advapi32.StartServiceCtrlDispatcherW(table):
        error = ctypes.get_last_error()
        if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            raise NotStartedByServiceManager("not started by the Windows service manager")
        raise ctypes.WinError(error)
