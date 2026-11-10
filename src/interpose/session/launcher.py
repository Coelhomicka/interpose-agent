from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.audit import AuditLogger
from .isolation.base import IsolationError
from .isolation.factory import create_isolation_backend
from .profile import SessionProfile

DEFAULT_PASSTHROUGH_ENVIRONMENT = frozenset(
    {
        "APPDATA",
        "COLORTERM",
        "COMSPEC",
        "DISPLAY",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LOCALAPPDATA",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROMPT",
        "PSMODULEPATH",
        "PUBLIC",
        "SHELL",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WAYLAND_DISPLAY",
        "WINDIR",
        "XDG_RUNTIME_DIR",
    }
)


PROXY_PLACEHOLDER = "${INTERPOSE_PROXY}"


@dataclass(frozen=True)
class HttpsProxySettings:
    """Transparent mode: route the agent's HTTP(S) through the broker's proxy port.

    ``ca_certificate`` is the broker CA alone (for tools that add to their roots);
    ``trust_bundle`` is the public roots plus that CA (for tools whose variable
    replaces their roots). Neither touches the operating system's trust store.
    """

    url: str
    ca_certificate: Path
    trust_bundle: Path
    curl_home: Path | None = None


def https_proxy_environment(settings: HttpsProxySettings, *, windows: bool | None = None) -> dict[str, str]:
    windows = os.name == "nt" if windows is None else windows
    bundle = str(settings.trust_bundle)
    environment = {
        "HTTPS_PROXY": settings.url,
        "https_proxy": settings.url,
        "HTTP_PROXY": settings.url,
        "http_proxy": settings.url,
        # The explicit broker transport (INTERPOSE_PROXY) and local servers stay direct.
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
        # Node's built-in fetch and http honor the variables above only with this.
        "NODE_USE_ENV_PROXY": "1",
        "NODE_EXTRA_CA_CERTS": str(settings.ca_certificate),
        "SSL_CERT_FILE": bundle,
        "REQUESTS_CA_BUNDLE": bundle,
        "CURL_CA_BUNDLE": bundle,
        "INTERPOSE_HTTPS_PROXY": settings.url,
    }
    git_config = [("http.sslCAInfo", bundle)]
    if windows:
        # Git for Windows defaults to Schannel, which reads only the Windows store.
        git_config.append(("http.sslBackend", "openssl"))
    if settings.curl_home is not None:
        # curl built on Schannel (Windows' own and Git's) ignores CURL_CA_BUNDLE.
        environment["CURL_HOME"] = str(settings.curl_home)
    environment["GIT_CONFIG_COUNT"] = str(len(git_config))
    for index, (key, value) in enumerate(git_config):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


class SessionLaunchError(RuntimeError):
    pass


class ReferenceChecker(Protocol):
    def exists(self, reference: str) -> bool: ...


def expand_proxy_placeholder(public_environment: Mapping[str, str], proxy_base: str | None) -> dict[str, str]:
    """Replace ``${INTERPOSE_PROXY}`` with the broker's local-transport base URL.

    The base already carries the active project (``.../p/<id>/proxy``), so a
    profile written once works in development and against the installed service.
    """
    expanded: dict[str, str] = {}
    for name, value in public_environment.items():
        if PROXY_PLACEHOLDER in value:
            if proxy_base is None:
                raise SessionLaunchError(f"{name} uses {PROXY_PLACEHOLDER} but no broker address is known")
            value = value.replace(PROXY_PLACEHOLDER, proxy_base.rstrip("/"))
        expanded[name] = value
    return expanded


def write_curl_config(directory: Path, trust_bundle: Path, *, windows: bool | None = None) -> Path:
    """A curl config for the session: the user's own (if any) plus the trust bundle.

    Schannel also checks revocation, which a local CA without a CRL cannot answer;
    best-effort revocation skips only that unknown status, not a revoked one.
    """
    windows = os.name == "nt" if windows is None else windows
    lines: list[str] = []
    for candidate in _user_curl_configs():
        try:
            lines.append(candidate.read_text(encoding="utf-8").rstrip())
            break
        except (OSError, UnicodeDecodeError):
            continue
    lines.append(f'cacert = "{trust_bundle.as_posix()}"')
    if windows:
        lines.append("ssl-revoke-best-effort")
    content = "\n".join(lines) + "\n"
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("_curlrc", ".curlrc"):
        (directory / name).write_text(content, encoding="utf-8")
    return directory


def _user_curl_configs() -> list[Path]:
    roots = [os.environ.get("CURL_HOME"), os.environ.get("XDG_CONFIG_HOME"), os.environ.get("HOME"),
             os.environ.get("APPDATA"), os.environ.get("USERPROFILE")]
    return [Path(root) / name for root in roots if root for name in (".curlrc", "_curlrc")
            if (Path(root) / name).is_file()]


def build_session_environment(
    profile: SessionProfile,
    *,
    agent: str,
    session: str,
    source: Mapping[str, str] | None = None,
    proxy_base: str | None = None,
    https_proxy: HttpsProxySettings | None = None,
) -> dict[str, str]:
    inherited = source if source is not None else os.environ
    allowed_names = DEFAULT_PASSTHROUGH_ENVIRONMENT | set(profile.runtime.pass_environment)
    environment = {
        name: value
        for name, value in inherited.items()
        if name.upper() in allowed_names or name in profile.runtime.pass_environment
    }

    environment.update(expand_proxy_placeholder(profile.public_environment, proxy_base))
    environment.update(profile.environment)
    environment["INTERPOSE_AGENT"] = agent
    environment["INTERPOSE_SESSION"] = session
    environment["INTERPOSE_MODE"] = "reference-only"
    if proxy_base:
        # Agents and their instructions build broker URLs from this:
        # "$INTERPOSE_PROXY/api.example.com/v1/...".
        environment["INTERPOSE_PROXY"] = proxy_base.rstrip("/")
    environment.pop("INTERPOSE_MASTER_KEY", None)
    environment.pop("INTERPOSE_HOME", None)

    if https_proxy is not None and not profile.runtime.http_proxy:
        environment.update(https_proxy_environment(https_proxy))

    if profile.runtime.http_proxy:
        environment["HTTP_PROXY"] = profile.runtime.http_proxy
        environment["http_proxy"] = profile.runtime.http_proxy
        environment["NO_PROXY"] = ""
        environment["no_proxy"] = ""
        environment["INTERPOSE_HTTP_PROXY"] = profile.runtime.http_proxy
        environment.pop("HTTPS_PROXY", None)
        environment.pop("https_proxy", None)

    return environment


@dataclass
class SessionLauncher:
    secret_store: ReferenceChecker
    # None when the vault (and its audit log) belong to the OS service; the
    # broker audits every use of a secret on its side either way.
    audit_logger: AuditLogger | None
    runtime_home: Path
    proxy_base: str | None = None
    https_proxy: HttpsProxySettings | None = None

    def validate_bindings(self, profile: SessionProfile) -> None:
        missing = [reference for reference in profile.environment.values() if not self.secret_store.exists(reference)]
        if missing:
            raise SessionLaunchError(f"unknown secret references: {', '.join(sorted(missing))}")

    def run(
        self,
        command: Sequence[str],
        *,
        profile: SessionProfile,
        agent: str,
        session: str | None = None,
        cwd: Path | str | None = None,
    ) -> int:
        if not command:
            raise SessionLaunchError("session command cannot be empty")
        self.validate_bindings(profile)
        session_id = session or uuid.uuid4().hex
        environment = build_session_environment(profile, agent=agent, session=session_id,
                                                proxy_base=self.proxy_base, https_proxy=self.https_proxy)
        working_directory = Path(cwd or Path.cwd()).resolve()
        backend = create_isolation_backend(
            profile.runtime.isolation,
            session=session_id,
            runtime_home=self.runtime_home,
        )
        started = time.perf_counter()
        references = sorted(set(profile.environment.values()))
        try:
            return_code = backend.run(
                list(command),
                environment=environment,
                cwd=working_directory,
            )
            status = "success" if return_code == 0 else "error"
        except (OSError, IsolationError) as exc:
            return_code = 1
            status = "launch-error"
            raise SessionLaunchError(str(exc)) from exc
        finally:
            if self.audit_logger is not None:
                self.audit_logger.record(
                    session=session_id,
                    agent=agent,
                    secret_reference=",".join(references) or "none",
                    destination="local-process",
                    action="SESSION_RUN",
                    policy_result="not-applicable",
                    status=status if "status" in locals() else "launch-error",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    details={
                        "executable": Path(command[0]).name,
                        "isolation": backend.name,
                        "return_code": return_code if "return_code" in locals() else 1,
                    },
                )
        return return_code
