"""The opening banner and the session summary printed by ``interpose up``.

Rendered with rich: a cyan-to-violet gradient across the columns on terminals
that support color, plain text when output is redirected or ``NO_COLOR`` is set,
and a one-line title when the console cannot encode the block characters (an
old Windows code page, for example).
"""

from __future__ import annotations

import importlib.metadata

from rich.console import Console
from rich.text import Text

LOGO = (
    "██╗███╗   ██╗████████╗███████╗██████╗ ██████╗  ██████╗ ███████╗███████╗",
    "██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝",
    "██║██╔██╗ ██║   ██║   █████╗  ██████╔╝██████╔╝██║   ██║███████╗█████╗  ",
    "██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║╚════██║██╔══╝  ",
    "██║██║ ╚████║   ██║   ███████╗██║  ██║██║     ╚██████╔╝███████║███████╗",
    "╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝",
)
TAGLINE = "credentials for AI agents — the agent holds a reference, never the key"

_START = (34, 211, 238)  # cyan
_END = (167, 139, 250)  # violet


def _version() -> str:
    try:
        return importlib.metadata.version("interpose")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def _gradient_line(line: str) -> Text:
    text = Text(line)
    width = max(len(line) - 1, 1)
    for column, char in enumerate(line):
        if char == " ":
            continue
        t = column / width
        rgb = tuple(round(a + (b - a) * t) for a, b in zip(_START, _END, strict=True))
        text.stylize(f"bold {_hex(rgb)}", column, column + 1)
    return text


def _can_draw(console: Console) -> bool:
    try:
        "█╗═║╔╝".encode(console.encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def console() -> Console:
    return Console(highlight=False, soft_wrap=False)


def print_banner(out: Console | None = None) -> None:
    out = out or console()
    out.print()
    if _can_draw(out) and out.width >= len(LOGO[0]) + 2:
        for line in LOGO:
            out.print(Text("  ").append_text(_gradient_line(line)))
        out.print(Text(f"  {TAGLINE}", style="dim"))
        out.print(Text(f"  v{_version()}", style="dim"))
    else:
        out.print(Text(f"  Interpose v{_version()}", style="bold"))
        out.print(Text("  credentials for AI agents - the agent holds a reference, never the key", style="dim"))
    out.print()


def print_fields(fields: list[tuple[str, str]], out: Console | None = None) -> None:
    """Aligned ``label  value`` lines; URLs are clickable where the terminal allows."""
    out = out or console()
    width = max(len(label) for label, _ in fields)
    for label, value in fields:
        line = Text(f"  {label.ljust(width)}  ", style="dim")
        if value.startswith("http"):
            line.append(value, style=f"bold cyan link {value}")
        else:
            line.append(value, style="bold")
        out.print(line)
