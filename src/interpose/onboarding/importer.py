"""Move plaintext credentials found by the scanner into the vault.

Each moved value is stored under a ``secret://`` reference and replaced in place by
that reference, so the file keeps its format and the application keeps reading
the same variable. For providers the broker understands, a policy is created (or,
with the service, suggested in the dashboard, where approving it may need Windows
Hello).

Values the broker cannot carry yet (database passwords, AWS keys, private keys)
are only reported by default: replacing them would break the application, which
still needs the plaintext.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.references import normalize_secret_reference
from .scanner import Finding


class SecretSink(Protocol):
    def store(self, reference: str, value: str, provider: str | None) -> None: ...


@dataclass
class ImportItem:
    finding: Finding
    reference: str
    move: bool
    reason: str


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-._").lower()
    return slug or "secret"


def plan(findings: Iterable[Finding], *, namespace: str, include_unbrokered: bool = False) -> list[ImportItem]:
    """Decide a reference and an action for every finding. Nothing is written."""
    items: list[ImportItem] = []
    by_value: dict[str, str] = {}
    used: set[str] = set()
    for finding in findings:
        provider = finding.provider
        if finding.value in by_value:
            reference = by_value[finding.value]  # the same value in several files is one secret
        else:
            folder = provider.id if provider and provider.brokerable else _slug(namespace)
            base = f"secret://{folder}/{_slug(finding.key.rsplit('.', 1)[-1].rsplit('/', 1)[-1])}"
            reference, counter = base, 2
            while reference in used:
                reference, counter = f"{base}-{counter}", counter + 1
            reference = normalize_secret_reference(reference)
            used.add(reference)
            by_value[finding.value] = reference

        if not finding.rewritable:
            move, reason = False, "found in source code: move it to configuration by hand"
        elif finding.brokerable:
            move, reason = True, f"{provider.name}: the broker injects it"
        elif include_unbrokered:
            move, reason = True, "moved on request; the application now sees a reference and needs a broker for it"
        else:
            note = provider.note if provider and provider.note else "the broker cannot inject this kind of value yet"
            move, reason = False, note
        items.append(ImportItem(finding, reference, move, reason))
    return items


def _rewrite(path: Path, replacements: list[tuple[int, int, int, str, str]]) -> None:
    """Apply (line, start, end, expected, new) replacements; refuses if the file changed."""
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    lines = text.splitlines(keepends=True)
    for line_number, start, end, expected, new in sorted(replacements, key=lambda r: (r[0], -r[1])):
        line = lines[line_number - 1]
        if line[start:end] != expected:
            raise RuntimeError(f"{path} changed while importing (line {line_number}); nothing was rewritten")
        lines[line_number - 1] = line[:start] + new + line[end:]
    temporary = path.with_name(path.name + ".interpose-tmp")
    temporary.write_bytes("".join(lines).encode("utf-8"))
    os.replace(temporary, path)


def apply(items: Iterable[ImportItem], sink: SecretSink) -> list[ImportItem]:
    """Store every value to move, then rewrite the files. Returns the moved items.

    Values are stored before any file changes, so a failure leaves the files as
    they were (and the vault with a copy, which is harmless).
    """
    moving = [item for item in items if item.move]
    stored: set[str] = set()
    for item in moving:
        if item.reference not in stored:
            provider = item.finding.provider.id if item.finding.brokerable else None
            sink.store(item.reference, item.finding.secret_value, provider)
            stored.add(item.reference)

    by_file: dict[Path, list[tuple[int, int, int, str, str]]] = {}
    for item in moving:
        finding = item.finding
        by_file.setdefault(finding.path, []).append(
            (finding.line, finding.start, finding.end, finding.value, item.reference)
        )
    for path, replacements in by_file.items():
        _rewrite(path, replacements)
    return moving
