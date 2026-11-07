"""Talk to an installed service from the user's side.

The user's CLI cannot open the vault anymore; it asks the service instead. Before
it sends the user to a dashboard to type a secret, it checks that the process
listening on the dashboard port is the service itself, so a process that grabbed
the port first (while the service was restarting, say) cannot pose as the
dashboard and collect the value.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .layout import ServiceEndpoint, ServiceLayout
from .win32 import listener_pid, service_pid


class ServiceUnavailable(RuntimeError):
    pass


@dataclass
class ServiceClient:
    endpoint: ServiceEndpoint
    control_token: str

    @classmethod
    def connect(cls, layout: ServiceLayout | None = None) -> ServiceClient:
        layout = layout or ServiceLayout.default()
        try:
            endpoint = ServiceEndpoint.from_json(layout.endpoint_file.read_text(encoding="utf-8"))
            token = layout.control_token_file.read_text(encoding="utf-8").strip()
        except (OSError, ValueError, KeyError) as exc:
            raise ServiceUnavailable(
                "the Interpose service is installed but not running; start it with `interpose service start`"
            ) from exc
        return cls(endpoint=endpoint, control_token=token)

    def verify_identity(self) -> None:
        """Refuse to continue unless the dashboard port belongs to the service."""
        expected = service_pid()
        if expected is None:
            raise ServiceUnavailable("the Interpose service is not running; start it with `interpose service start`")
        for url in (self.endpoint.dashboard_url, self.endpoint.proxy_url):
            port = urlsplit(url).port
            actual = listener_pid(port) if port else None
            if actual != expected:
                raise ServiceUnavailable(
                    f"port {port} is held by process {actual}, not by the Interpose service ({expected}); "
                    "refusing to continue. Stop that process and restart the service."
                )

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            response = httpx.request(
                method,
                f"{self.endpoint.dashboard_url}{path}",
                headers={"Authorization": f"Bearer {self.control_token}"},
                timeout=10,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise ServiceUnavailable(f"cannot reach the Interpose service: {exc}") from exc
        if response.status_code != 200:
            raise ServiceUnavailable(f"the Interpose service refused the request ({response.status_code})")
        return response.json()

    def login_url(self, working_directory: Path) -> str:
        path = self._request("POST", "/control/login", json={"cwd": str(working_directory)})["path"]
        return f"{self.endpoint.dashboard_url}{path}"

    def project_id(self, working_directory: Path) -> str | None:
        return self._request("GET", "/control/project", params={"cwd": str(working_directory)})["id"]

    def secret_exists(self, reference: str, working_directory: Path) -> bool:
        params = {"reference": reference, "cwd": str(working_directory)}
        return bool(self._request("GET", "/control/secret-exists", params=params)["exists"])

    def proxy_base(self, working_directory: Path) -> str:
        project_id = self.project_id(working_directory)
        prefix = f"/p/{project_id}" if project_id else ""
        return f"{self.endpoint.proxy_url}{prefix}/proxy"
