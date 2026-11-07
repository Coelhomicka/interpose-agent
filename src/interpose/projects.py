"""Operator-controlled registry mapping folders to project scopes."""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .core.scopes import PROJECT_ID_RE, ScopeError


@dataclass(frozen=True)
class Project:
    id: str
    name: str
    root: str
    created_at: datetime


def display_root(path: Path | str) -> str:
    return str(Path(path).expanduser().resolve())


def canonical_root(path: Path | str) -> str:
    """Comparison key for a folder: resolved, and case-folded where the OS is."""
    return os.path.normcase(display_root(path))


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    return slug or "project"


class ProjectRegistry:
    def __init__(self, database_path: Path | str) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    root TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Project:
        return Project(
            id=row["id"],
            name=row["name"],
            root=row["root"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def list(self) -> list[Project]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM projects ORDER BY name ASC").fetchall()
        return [self._from_row(row) for row in rows]

    def get(self, project_id: str) -> Project | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return self._from_row(row) if row else None

    def find_for_path(self, path: Path | str) -> Project | None:
        """The registered project whose root is ``path`` or its nearest ancestor."""
        candidate = Path(canonical_root(path))
        roots = {canonical_root(project.root): project for project in self.list()}
        for directory in (candidate, *candidate.parents):
            project = roots.get(str(directory))
            if project is not None:
                return project
        return None

    def register(self, root: Path | str, name: str | None = None) -> Project:
        shown = display_root(root)
        existing = self.find_exact(shown)
        if existing is not None:
            return existing
        display_name = (name or Path(shown).name or "project").strip()
        base = _slug(display_name)
        taken = {project.id for project in self.list()}
        project_id, suffix = base, 2
        while project_id in taken:
            project_id = f"{base}-{suffix}"
            suffix += 1
        if not PROJECT_ID_RE.fullmatch(project_id):
            raise ScopeError(f"cannot derive a valid project id from {display_name!r}")
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO projects (id, name, root, created_at) VALUES (?, ?, ?, ?)",
                (project_id, display_name, shown, now),
            )
        return Project(id=project_id, name=display_name, root=shown, created_at=datetime.fromisoformat(now))

    def find_exact(self, root: Path | str) -> Project | None:
        key = canonical_root(root)
        return next((project for project in self.list() if canonical_root(project.root) == key), None)
