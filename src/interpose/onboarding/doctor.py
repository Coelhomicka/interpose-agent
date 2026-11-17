"""`interpose doctor`: is this machine and this folder set up to keep secrets from agents?"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    status: str
    title: str
    detail: str = ""
    fix: str = ""


def run_checks(working_directory: Path, *, scan: Callable[[Path], list] | None = None) -> list[Check]:
    from ..core.elevation import is_elevated
    from ..service.layout import ServiceLayout, service_installed

    checks: list[Check] = []
    add = checks.append

    add(Check(OK, "Python", sys.version.split()[0]))

    if is_elevated():
        add(Check(WARN, "Shell", "this terminal is elevated (administrator)",
                  "Run agents from a normal terminal: an elevated agent can read anything."))
    if os.environ.get("INTERPOSE_MASTER_KEY"):
        add(Check(WARN, "INTERPOSE_MASTER_KEY", "the master key is in the environment, where agents can read it",
                  "Unset it; the vault keeps its key in a protected file."))

    installed = service_installed()
    if os.name == "nt":
        if installed:
            add(Check(OK, "Vault", f"protected by the Interpose service ({ServiceLayout.default().vault_dir})"))
            checks.extend(_service_checks())
        else:
            add(Check(WARN, "Vault", "development mode: the vault is in your profile, readable by your agents",
                      "Run `interpose setup` (one administrator prompt) to move it into the service."))
    else:
        add(Check(WARN, "Vault", "development mode: the OS service is Windows-only for now",
                  "Agents running as you can read ~/.interpose; see the threat model."))

    checks.extend(_agent_checks())

    if scan is not None:
        findings = scan(working_directory)
        if not findings:
            add(Check(OK, "Plaintext credentials", f"none found in {working_directory}"))
        else:
            brokerable = sum(1 for finding in findings if finding.brokerable)
            tracked = sum(1 for finding in findings if finding.tracked)
            detail = f"{len(findings)} found ({brokerable} can move to the vault now)"
            if tracked:
                detail += f"; {tracked} are committed to git — rotate those"
            add(Check(FAIL if tracked else WARN, "Plaintext credentials", detail,
                      "Run `interpose scan` to list them and `interpose import --apply` to move them."))

    gitignore = working_directory / ".gitignore"
    if (working_directory / ".git").exists():
        ignored = gitignore.is_file() and any(
            line.strip() in {".env", ".env*", ".env.*", "*.env", ".env.local"}
            for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if not ignored:
            add(Check(WARN, ".gitignore", "does not ignore .env files", "Add `.env*` to .gitignore."))
    return checks


def _service_checks() -> list[Check]:
    from ..service.client import ServiceClient, ServiceUnavailable

    try:
        client = ServiceClient.connect()
        client.verify_identity()
        health = client.health()
    except ServiceUnavailable:
        return [Check(OK, "Service", "installed, stopped (starts with `interpose up`)")]
    checks = [Check(OK, "Service", "running")]
    presence = health.get("presence")
    if presence == "enrolled":
        checks.append(Check(OK, "Windows Hello", "required to widen a policy"))
    elif presence == "missing":
        checks.append(Check(WARN, "Windows Hello", "not enrolled: any program running as you can widen a policy",
                            "Run `interpose service enroll`."))
    return checks


def _agent_checks() -> list[Check]:
    from .. import agents

    home = Path.home()
    present = [target for target in agents.global_targets(home) if target.path.is_file()]
    installed = [target for target in present if "secret://" in target.path.read_text(
        encoding="utf-8", errors="replace")]
    if installed:
        return [Check(OK, "Agent instructions", f"installed for {len(installed)} agent(s)")]
    found = [name for name in ("claude", "codex", "cursor", "gemini", "devin") if shutil.which(name)]
    detail = f"agents found: {', '.join(found)}" if found else "no user-level instructions installed"
    return [Check(WARN, "Agent instructions", detail,
                  "Run `interpose agents install` so agents use secret:// references.")]
