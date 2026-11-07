"""Whether the current process runs with administrator or root rights.

An elevated process can read any file and any process's memory, so nothing
Interpose sets up can contain an agent started that way.
"""

from __future__ import annotations

import ctypes
import os


def is_elevated() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0
