from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol


class IsolationError(RuntimeError):
    pass


class IsolationBackend(Protocol):
    name: str

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
    ) -> int:
        raise NotImplementedError


class NoIsolationBackend:
    name = "none"

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
    ) -> int:
        completed = subprocess.run(
            resolve_command(command, environment),
            cwd=str(cwd),
            env=dict(environment),
            check=False,
        )
        return int(completed.returncode)


def resolve_command(command: Sequence[str], environment: Mapping[str, str]) -> list[str]:
    """Resolve the executable against the *session's* PATH and PATHEXT.

    On Windows, CreateProcess searches the parent's PATH and only appends ``.exe``,
    so npm-installed CLIs (``codex.cmd``, ``gemini.cmd``) are not found by name.
    """
    resolved = list(command)
    if not resolved or os.path.dirname(resolved[0]):
        return resolved
    lookup = {key.upper(): value for key, value in environment.items()}
    previous_pathext = os.environ.get("PATHEXT")
    try:
        if os.name == "nt" and "PATHEXT" in lookup:
            os.environ["PATHEXT"] = lookup["PATHEXT"]
        found = shutil.which(resolved[0], path=lookup.get("PATH"))
    finally:
        if os.name == "nt" and previous_pathext is not None:
            os.environ["PATHEXT"] = previous_pathext
    if found:
        resolved[0] = found
    return resolved
