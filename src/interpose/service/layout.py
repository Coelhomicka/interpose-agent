"""Where an installed service keeps its code, its vault and what it publishes to clients."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROXY_PORT = 9876
DEFAULT_DASHBOARD_PORT = 18888


@dataclass(frozen=True)
class ServiceLayout:
    """Folders of an installed service.

    * ``program_dir`` - the private Python runtime and the installed package.
      Writable by administrators only, so the user cannot patch the code the
      service runs.
    * ``vault_dir`` - ``runtime.db``, ``audit.db`` and ``master.key``. Readable by
      the service account, SYSTEM and administrators; not by the user.
    * ``client_dir`` - what clients need to find and drive the service: the
      endpoint file and the control token. Readable by the installing user.
    """

    program_dir: Path
    data_dir: Path

    @classmethod
    def default(cls) -> ServiceLayout:
        # ProgramW6432 is the 64-bit Program Files even from a 32-bit interpreter.
        program_files = Path(
            os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES") or r"C:\Program Files"
        )
        program_data = Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData")
        return cls(program_dir=program_files / "Interpose", data_dir=program_data / "Interpose")

    @property
    def python_dir(self) -> Path:
        return self.program_dir / "python"

    @property
    def python_exe(self) -> Path:
        return self.python_dir / "python.exe"

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vault"

    @property
    def client_dir(self) -> Path:
        return self.data_dir / "client"

    @property
    def endpoint_file(self) -> Path:
        return self.client_dir / "endpoint.json"

    @property
    def control_token_file(self) -> Path:
        return self.client_dir / "control.token"

    @property
    def log_file(self) -> Path:
        return self.vault_dir / "service.log"


@dataclass(frozen=True)
class ServiceEndpoint:
    proxy_url: str
    dashboard_url: str
    pid: int

    def to_json(self) -> str:
        return json.dumps({"proxy_url": self.proxy_url, "dashboard_url": self.dashboard_url, "pid": self.pid})

    @classmethod
    def from_json(cls, text: str) -> ServiceEndpoint:
        data = json.loads(text)
        return cls(proxy_url=str(data["proxy_url"]), dashboard_url=str(data["dashboard_url"]), pid=int(data["pid"]))


def service_installed(layout: ServiceLayout | None = None) -> bool:
    """True when an installed service has published its endpoint.

    ``INTERPOSE_HOME`` forces the self-hosted development mode, which is also what
    the test suite and the service itself rely on.
    """
    if os.environ.get("INTERPOSE_HOME"):
        return False
    if os.name != "nt":
        return False
    return (layout or ServiceLayout.default()).endpoint_file.is_file()
