"""Secret and policy scopes.

A secret or policy lives either in the ``global`` scope or in one project's scope.
Resolution walks a chain: the active project's scope first, then ``global``. The
same ``secret://`` reference can therefore mean a project-specific value inside
one project and the shared value everywhere else.

Which project is active is decided by the operator-controlled project registry,
never by a file in the workspace, so an agent cannot point a session at another
project's secrets by editing the repository.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

GLOBAL_SCOPE = "global"
PROJECT_SCOPE_PREFIX = "project:"
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class ScopeError(ValueError):
    pass


def project_scope(project_id: str) -> str:
    if not PROJECT_ID_RE.fullmatch(project_id):
        raise ScopeError(f"invalid project id: {project_id!r}")
    return f"{PROJECT_SCOPE_PREFIX}{project_id}"


def validate_scope(scope: str) -> str:
    if scope == GLOBAL_SCOPE:
        return scope
    if scope.startswith(PROJECT_SCOPE_PREFIX):
        project_scope(scope[len(PROJECT_SCOPE_PREFIX):])
        return scope
    raise ScopeError(f"invalid scope: {scope!r}")


@dataclass
class ScopeContext:
    """The active project for this runtime process. Mutable so the dashboard can
    register the working folder as a project without restarting the broker."""

    project_id: str | None = None

    def chain(self) -> tuple[str, ...]:
        if self.project_id:
            return (project_scope(self.project_id), GLOBAL_SCOPE)
        return (GLOBAL_SCOPE,)

    @property
    def project_scope(self) -> str | None:
        return project_scope(self.project_id) if self.project_id else None
