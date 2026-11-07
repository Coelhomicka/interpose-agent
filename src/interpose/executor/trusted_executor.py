from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.audit import AuditLogger
from ..core.policies import PolicyEngine
from ..core.redaction import SecretRedactionEngine
from ..core.references import collect_secret_references
from ..core.substitution import SecretSubstitutionEngine
from ..models import DestinationContext, ExecutionResult, ResolvedSecret
from ..secrets.base import SecretStore
from .curl_config import CurlConfigError, split_secret_arguments


class PolicyViolationError(RuntimeError):
    pass


class ExecutionPreparationError(RuntimeError):
    pass


URL_RE = re.compile(r"https?://[^\s'\"`]+")

# curl treats a bare ``host.tld/path`` argument as a URL. Anything shaped like one is
# counted as a destination so it cannot ride along next to an allowed https:// URL.
# Filenames such as ``out.json`` also match; that is a deliberate fail-closed choice.
BARE_HOST_RE = re.compile(
    r"^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\]|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})"
    r"(?::\d+)?(?:[/?#].*)?$"
)

# Options that add destinations, reroute traffic, or read extra arguments from a file,
# all of which defeat inferring the destination from argv.
_CURL_FORBIDDEN_LONG_OPTIONS = {
    "--config",
    "--next",
    "--url",
    "--proxy",
    "--preproxy",
    "--socks4",
    "--socks4a",
    "--socks5",
    "--socks5-hostname",
    "--resolve",
    "--connect-to",
    "--doh-url",
    "--location",
    "--location-trusted",
    "--proxy-user",
    "--variable",
    "--expand-url",
}
_CURL_FORBIDDEN_SHORT_OPTIONS = {"K", "x", "L", "U", ":"}


def _is_curl(command: Sequence[str]) -> bool:
    return bool(command) and re.split(r"[\\/]", command[0])[-1].lower() in {"curl", "curl.exe"}


def _forbidden_curl_option(command: Sequence[str]) -> str | None:
    for token in command[1:]:
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            if name in _CURL_FORBIDDEN_LONG_OPTIONS:
                return name
        elif token.startswith("-") and len(token) > 1:
            cluster = token[1:]
            if cluster == ":" or (cluster.isalpha() and _CURL_FORBIDDEN_SHORT_OPTIONS & set(cluster)):
                return token
    return None


def _infer_method(command: Sequence[str]) -> str:
    if not command:
        return "EXEC"
    command_name = re.split(r"[\\/]", command[0])[-1].lower()
    if command_name not in {"curl", "curl.exe"}:
        return "EXEC"
    method = "GET"
    for index, token in enumerate(command):
        if token == "-X" and index + 1 < len(command):
            method = command[index + 1].upper()
    return method


def _infer_destinations(command: Sequence[str]) -> list[DestinationContext]:
    method = _infer_method(command)
    destinations: list[DestinationContext] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        parsed = urlparse(url)
        if not parsed.hostname:
            return
        host = parsed.hostname.lower()
        if parsed.port:
            host = f"{host}:{parsed.port}"
        key = f"{host}:{method}"
        if key not in seen:
            seen.add(key)
            destinations.append(
                DestinationContext(
                    host=host,
                    method=method,
                    scheme=parsed.scheme,
                    url=parsed.geturl(),
                    path=parsed.path or "/",
                )
            )

    curl = _is_curl(command)
    for token in command[1:] if command else ():
        matched_url = False
        for match in URL_RE.finditer(token):
            matched_url = True
            add(match.group(0))
        if curl and not matched_url and not token.startswith("-") and BARE_HOST_RE.match(token):
            # curl defaults schemeless URLs to http; record that so policy sees it.
            add(f"http://{token}")
    return destinations


@dataclass
class TrustedExecutor:
    secret_store: SecretStore
    policy_engine: PolicyEngine
    audit_logger: AuditLogger
    redaction_engine: SecretRedactionEngine
    agent_name: str = "unknown"

    def _resolve_secret(self, reference) -> ResolvedSecret:
        return self.secret_store.resolve(reference)

    def execute(
        self,
        command: Sequence[str],
        *,
        session: str = "local",
        agent: str | None = None,
        destination: DestinationContext | None = None,
    ) -> ExecutionResult:
        if not command:
            raise ExecutionPreparationError("command cannot be empty")

        start = time.perf_counter()
        resolved_agent = (agent or self.agent_name or "unknown").strip() or "unknown"
        references = collect_secret_references(command)

        def deny(reason: str, host: str) -> PolicyViolationError:
            self.audit_logger.record(
                session=session,
                agent=resolved_agent,
                secret_reference=",".join(reference.canonical for reference in references),
                destination=host,
                action="EXEC",
                policy_result="deny",
                status="blocked",
                duration_ms=int((time.perf_counter() - start) * 1000),
                details={"reason": reason},
            )
            return PolicyViolationError(reason)

        if references:
            # The subprocess will hold the plaintext, so the operator must opt each
            # secret into this mode; a host allow-list alone does not imply it.
            for reference in references:
                if not self.policy_engine.allows_exec(reference):
                    raise deny(f"{reference.canonical} does not permit interpose-exec (allow_exec: true)", "unknown")
            # Only curl: any other program handed a credential can do anything with
            # it, and argv inference cannot tell what that would be.
            if not _is_curl(command):
                raise deny("interpose-exec only runs curl with secret references; use the broker instead", "unknown")
            forbidden = _forbidden_curl_option(command)
            if forbidden:
                raise deny(f"curl option {forbidden} is not allowed with secret references", "unknown")
            try:
                split_secret_arguments(command)
            except CurlConfigError as exc:
                raise deny(str(exc), "unknown") from exc

        inferred_destinations = _infer_destinations(command)
        if destination is not None:
            stray = sorted({context.host for context in inferred_destinations} - {destination.host.lower()})
            if references and stray:
                raise deny(
                    f"command addresses hosts other than the explicit destination: {', '.join(stray)}",
                    ",".join(stray),
                )
            inferred_destinations = [destination]

        if references and not inferred_destinations:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self.audit_logger.record(
                session=session,
                agent=resolved_agent,
                secret_reference=",".join(reference.canonical for reference in references),
                destination="unknown",
                action="EXEC",
                policy_result="deny",
                status="blocked",
                duration_ms=duration_ms,
                details={"reason": "destination could not be inferred"},
            )
            raise PolicyViolationError("destination could not be inferred for secret usage")

        if len({context.host for context in inferred_destinations}) > 1:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self.audit_logger.record(
                session=session,
                agent=resolved_agent,
                secret_reference=",".join(reference.canonical for reference in references),
                destination=",".join(context.host for context in inferred_destinations),
                action="EXEC",
                policy_result="deny",
                status="blocked",
                duration_ms=duration_ms,
                details={"reason": "multiple destinations detected"},
            )
            raise PolicyViolationError("multiple destinations detected; explicit destination handling is required")

        active_destination = (
            inferred_destinations[0]
            if inferred_destinations
            else DestinationContext(host="unknown", method="EXEC")
        )

        for reference in references:
            decision = self.policy_engine.evaluate(reference, active_destination)
            if not decision.allowed:
                duration_ms = int((time.perf_counter() - start) * 1000)
                self.audit_logger.record(
                    session=session,
                    agent=resolved_agent,
                    secret_reference=reference.canonical,
                    destination=active_destination.host,
                    action=f"HTTP_{active_destination.method}" if active_destination.method != "EXEC" else "EXEC",
                    policy_result="deny",
                    status="blocked",
                    duration_ms=duration_ms,
                    details={"reason": decision.reason},
                )
                raise PolicyViolationError(decision.reason)

        # Secrets travel on stdin as curl config, never in argv, where every process
        # of the same user could read them.
        argv, config = split_secret_arguments(command) if references else (list(command), "")
        substitution = SecretSubstitutionEngine(self._resolve_secret)
        substitution_result = substitution.substitute(config)
        resolved_config = substitution_result.value
        resolved_values = [resolution.value for resolution in substitution_result.resolutions]
        self.redaction_engine.register_many(resolved_values)

        try:
            completed = subprocess.run(
                argv,
                input=resolved_config if config else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            stdout = self.redaction_engine.redact(completed.stdout)
            stderr = self.redaction_engine.redact(completed.stderr)
            status = "success" if completed.returncode == 0 else "error"
            policy_result = "allow"
            return_code = int(completed.returncode)
        except Exception as exc:
            stdout = ""
            stderr = self.redaction_engine.redact(str(exc))
            status = "error"
            policy_result = "allow"
            return_code = 1
        duration_ms = int((time.perf_counter() - start) * 1000)
        self.audit_logger.record(
            session=session,
            agent=resolved_agent,
            secret_reference=",".join(reference.canonical for reference in references) or "none",
            destination=active_destination.host,
            action=f"HTTP_{active_destination.method}" if active_destination.method != "EXEC" else "EXEC",
            policy_result=policy_result,
            status=status,
            duration_ms=duration_ms,
            details={"return_code": return_code},
        )
        return ExecutionResult(
            command=tuple(command),
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            allowed=True,
            policy_result=policy_result,
            destination=active_destination.host,
            duration_ms=duration_ms,
        )
