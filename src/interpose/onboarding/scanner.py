"""Find plaintext credentials in a project, in the config files of every common stack.

Config files are parsed line by line, keeping each value's exact position, so a
found value can later be replaced by its ``secret://`` reference without
reformatting the file. Source files are only searched for credentials with an
unmistakable shape (``ghp_...``, ``sk-ant-...``, private key blocks) and are
reported, never rewritten.

Nothing here prints or returns a value except through ``Finding.value``, which is
excluded from ``repr`` and from ``Finding.public()``.
"""

from __future__ import annotations

import fnmatch
import json
import math
import re
import subprocess
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .providers import PROVIDERS, Provider, identify
from .providers import provider as provider_by_id

MAX_FILE_BYTES = 512 * 1024

SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "target", "vendor", ".next", ".nuxt", ".svelte-kit",
    ".terraform", ".gradle", ".idea", "coverage", "bin", "obj", ".angular", ".turbo", ".cache", "site-packages",
}

# Example and template files usually hold fake values on purpose.
_EXAMPLE_RE = re.compile(r"(?:^|[._-])(?:example|sample|template|dist|tpl|defaults?)(?:$|[._-])", re.IGNORECASE)

_SECRET_NAME_RE = re.compile(
    r"(?:secret|token|passw(?:or)?d|passphrase|\bpwd\b|_pwd|pwd_|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key"
    r"|client[_.-]?secret|auth(?:_|-|\.)?token|_auth\b|authtoken|credential|conn(?:ection)?[_.-]?str"
    r"|\bdsn\b|_dsn|database[_.-]?url|db[_.-]?url|signing[_.-]?key|webhook[_.-]?secret|master[_.-]?key|salt)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"^(?:|null|none|nil|true|false|yes|no|changeme|change[_-]?me|todo|tbd|placeholder|dummy|example|secret"
    r"|password|redacted|\*+|x+|\.+|-+)$|your[_ -]|<[^>]*>|\$\{|\{\{|^\$[A-Za-z_]|^%[A-Za-z_]|secret://"
    r"|xxxx|example\.com|localhost|127\.0\.0\.1|^env\(|process\.env|os\.environ|getenv",
    re.IGNORECASE,
)


_CONNECTION_PASSWORD_RE = re.compile(r"(?i)(?:^|;)\s*(?:password|pwd)\s*=\s*[^;\s]{4,}")


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int  # 1-based
    key: str
    value: str = field(repr=False)
    start: int = 0  # value span inside the line, for rewriting
    end: int = 0
    format: str = ""
    stack: str = ""
    provider: Provider | None = None
    rewritable: bool = False
    tracked: bool = False

    @property
    def brokerable(self) -> bool:
        return bool(self.provider and self.provider.brokerable)

    @property
    def secret_value(self) -> str:
        """The credential itself: ``value`` as written, with JSON string escapes decoded."""
        if self.format == "json" and "\\" in self.value:
            try:
                return json.loads(f'"{self.value}"')
            except ValueError:
                return self.value
        return self.value

    @property
    def masked(self) -> str:
        return f"{self.value[:4]}… ({len(self.value)} chars)"

    def public(self, root: Path) -> dict:
        try:
            relative = self.path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            relative = str(self.path)
        return {
            "file": relative,
            "line": self.line,
            "key": self.key,
            "masked": self.masked,
            "format": self.format,
            "stack": self.stack,
            "provider": self.provider.id if self.provider else None,
            "brokerable": self.brokerable,
            "rewritable": self.rewritable,
            "tracked_by_git": self.tracked,
        }


@dataclass(frozen=True)
class _Match:
    key: str
    start: int
    end: int


# --- line parsers --------------------------------------------------------------
# Each returns the key and the span of the value (without surrounding quotes).


def _unquote_span(line: str, start: int, end: int) -> tuple[int, int]:
    value = line[start:end]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return start + 1, end - 1
    return start, end


def _strip_inline_comment(line: str, start: int, end: int) -> int:
    value = line[start:end]
    if value[:1] in "\"'":
        return end
    position = value.find(" #")
    return start + position if position >= 0 else end


def _regex_parser(pattern: str, *, comments: str = "#", inline_comments: bool = False,
                  fixed_key: str | None = None) -> Callable[[str], Iterator[_Match]]:
    compiled = re.compile(pattern)

    def parse(line: str) -> Iterator[_Match]:
        if line.lstrip().startswith(tuple(comments)) if comments else False:
            return
        for match in compiled.finditer(line):
            start, end = match.span("val")
            while end > start and line[end - 1] in " \t\r":
                end -= 1
            if inline_comments:
                end = _strip_inline_comment(line, start, end)
                while end > start and line[end - 1] in " \t":
                    end -= 1
            start, end = _unquote_span(line, start, end)
            key = fixed_key or match.group("key").strip("\"' ")
            yield _Match(key, start, end)

    return parse


_PARSERS: dict[str, Callable[[str], Iterator[_Match]]] = {
    "dotenv": _regex_parser(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(?P<val>.*)$",
                            inline_comments=True),
    "properties": _regex_parser(r"^\s*(?P<key>[\w.\-\[\]]+)\s*[=:]\s*(?P<val>.*)$", comments="#!"),
    "yaml": _regex_parser(
        r"^\s*(?:-\s+)?(?P<key>[\"']?[\w.\-]+[\"']?)\s*:\s+(?P<val>[^|>{\[&*\s#][^#]*?)\s*(?:\s#.*)?$"
    ),
    "yaml-env-list": _regex_parser(r"^\s*-\s*[\"']?(?P<key>[A-Za-z_][\w.]*)=(?P<val>[^\"'\n]*)"),
    "json": _regex_parser(r"\"(?P<key>[^\"]+)\"\s*:\s*\"(?P<val>(?:[^\"\\]|\\.)*)\"", comments="//"),
    "toml": _regex_parser(r"^\s*(?P<key>[\w.\-\"]+)\s*=\s*(?P<val>\"[^\"]*\"|'[^']*')"),
    "ini": _regex_parser(r"^\s*(?P<key>[^=\s#;\[][^=]*?)\s*=\s*(?P<val>.*)$", comments="#;"),
    "netrc": _regex_parser(r"\bpassword\s+(?P<val>\S+)", fixed_key="password"),
    "php": _regex_parser(r"define\(\s*['\"](?P<key>\w+)['\"]\s*,\s*['\"](?P<val>[^'\"]*)['\"]", comments="/#*"),
    "python": _regex_parser(r"^\s*(?P<key>[A-Z][A-Z0-9_]*)\s*=\s*(?P<val>\"[^\"]+\"|'[^']+')"),
}


def _xml_parse(line: str) -> Iterator[_Match]:
    # The XML pattern has two alternatives with different group names.
    for match in re.finditer(
        r"<add\s+(?:key|name)=\"(?P<key>[^\"]+)\"\s+(?:value|connectionString)=\"(?P<val>[^\"]*)\""
        r"|<(?P<key2>password|passphrase|token|apiKey|secret)>(?P<val2>[^<]+)</",
        line,
    ):
        if match.group("key") is not None:
            yield _Match(match.group("key"), *match.span("val"))
        else:
            yield _Match(match.group("key2"), *match.span("val2"))


_PARSERS["xml"] = _xml_parse


@dataclass(frozen=True)
class _FileKind:
    patterns: tuple[str, ...]
    format: str
    stack: str


# Matched against the path relative to the scanned root (forward slashes), so a
# pattern can name a folder (``.streamlit/secrets.toml``).
FILE_KINDS: tuple[_FileKind, ...] = (
    _FileKind((".env", ".env.*", "*.env", ".flaskenv"), "dotenv", "dotenv (Node, Python, Ruby, PHP, Go, Docker...)"),
    _FileKind((".envrc",), "dotenv", "direnv"),
    _FileKind((".dev.vars",), "dotenv", "Cloudflare Workers"),
    _FileKind(("appsettings*.json",), "json", ".NET"),
    _FileKind(("secrets.json",), "json", ".NET user secrets"),
    _FileKind(("local.settings.json",), "json", "Azure Functions"),
    _FileKind((".mcp.json", "mcp.json", "*/mcp.json", "claude_desktop_config.json", "*/settings.local.json"),
              "json", "MCP / agent config"),
    _FileKind(("web.config", "app.config", "*.config", "settings.xml"), "xml", ".NET Framework / Maven"),
    _FileKind(("application*.properties", "gradle.properties", "local.properties", "*.properties"),
              "properties", "Java / Spring / Android"),
    _FileKind(("application*.yml", "application*.yaml", "bootstrap*.yml", "bootstrap*.yaml"), "yaml", "Spring"),
    _FileKind(("config/secrets.yml", "config/database.yml", "config/application.yml", "config/storage.yml"),
              "yaml", "Rails"),
    _FileKind(("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"),
              "yaml", "Docker Compose"),
    _FileKind(("values*.yaml", "values*.yml", "secrets.yaml", "secrets.yml", "serverless.yml", "app.yaml",
               ".yarnrc.yml", "*.yml", "*.yaml"), "yaml", "YAML config"),
    _FileKind((".streamlit/secrets.toml",), "toml", "Streamlit"),
    _FileKind(("wrangler.toml",), "toml", "Cloudflare Workers"),
    _FileKind(("*.tfvars", "*.auto.tfvars"), "toml", "Terraform"),
    _FileKind((".cargo/credentials.toml", "credentials.toml", "*.toml"), "toml", "TOML config"),
    _FileKind((".npmrc", ".pypirc", "pip.conf", "pip.ini", ".gemrc", "*.ini", "*.cfg"),
              "ini", "package managers / INI"),
    _FileKind((".netrc", "_netrc"), "netrc", "netrc"),
    _FileKind(("wp-config.php", "config.php", "*/config/*.php"), "php", "PHP / WordPress"),
    _FileKind(("settings.py", "*/settings.py", "*/settings/*.py", "config.py", "local_settings.py"),
              "python", "Python / Django"),
)

# Searched for unmistakable credential shapes only.
SOURCE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".kt", ".kts", ".cs",
    ".rs", ".swift", ".ex", ".exs", ".scala", ".dart", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
    ".ipynb", ".sql", ".tf", ".hcl", ".xml", ".gradle", ".md", ".txt", ".pem", ".key", ".vue", ".svelte",
}
_STRONG_PROVIDERS: tuple[Provider, ...] = tuple(
    p for p in PROVIDERS if p.value_pattern is not None and p.id != "connection-string"
)


def _file_kind(relative: str) -> _FileKind | None:
    name = relative.rsplit("/", 1)[-1]
    for kind in FILE_KINDS:
        for pattern in kind.patterns:
            if fnmatch.fnmatch(relative if "/" in pattern else name, pattern):
                return kind
    return None


def _entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values()) if value else 0.0


def classify(key: str, value: str) -> Provider | bool:
    """``Provider`` when the value is a known credential, ``True`` when it is a likely
    unknown credential, ``False`` when it is not a credential."""
    value = value.strip()
    known = identify(key, value)
    if known is not None and known.value_pattern is not None and known.value_pattern.search(value):
        if known.id == "connection-string" and re.search(r"@(?:localhost|127\.0\.0\.1|\[::1\])[:/]?", value):
            return False  # a local development database
        return known
    if _PLACEHOLDER_RE.search(value) or len(value) < 8:
        return False
    if _CONNECTION_PASSWORD_RE.search(value):  # ADO.NET / JDBC style "...;Password=...;"
        return provider_by_id("connection-string") or True
    if known is not None:
        return known  # a well-known variable name with a value of no fixed shape
    if _SECRET_NAME_RE.search(key) and _entropy(value) >= 2.5 and " " not in value:
        if re.fullmatch(r"[a-z][a-z0-9+.-]*://[^@\s]+", value):
            return False  # a plain URL is not a credential
        # Names, paths and references (``secretapi/teste``) are letters only; a
        # credential mixes in digits or symbols.
        return any(character.isdigit() for character in value) or bool(re.search(r"[^\w./-]", value))
    return False


def _plausible_token(line: str, start: int, token: str) -> bool:
    """Filter matches inside identifiers (``test_reference_...`` is not ``re_...``)
    and word-only matches (``sk-live-dashboard-test-value``): issued keys start at
    a word boundary and carry digits."""
    if start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
        return False
    return token.startswith("-----BEGIN") or any(character.isdigit() for character in token)


def _tracked_files(root: Path) -> set[Path] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--full-name"],
            capture_output=True, check=False, timeout=20,
        )
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or top.returncode != 0:
        return None
    toplevel = Path(top.stdout.strip())
    return {(toplevel / name).resolve() for name in result.stdout.decode("utf-8", "replace").split("\0") if name}


def iter_candidate_files(root: Path, paths: Iterable[Path] | None = None) -> Iterator[Path]:
    if paths:
        for path in paths:
            if path.is_dir():
                yield from iter_candidate_files(path)
            elif path.is_file():
                yield path
        return
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRECTORIES:
                    stack.append(entry)
            elif entry.is_file():
                yield entry


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def scan(root: Path, paths: Iterable[Path] | None = None, *, include_examples: bool = False) -> list[Finding]:
    root = root.resolve()
    tracked = _tracked_files(root) or set()
    findings: list[Finding] = []
    seen: set[tuple[Path, int, int]] = set()

    for path in iter_candidate_files(root, list(paths) if paths else None):
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        name = path.name
        if not include_examples and _EXAMPLE_RE.search(name.replace(".env", "", 1) if name.startswith(".env")
                                                      else name):
            continue
        kind = _file_kind(relative)
        is_source = path.suffix.lower() in SOURCE_SUFFIXES
        if kind is None and not is_source:
            continue
        text = _read_text(path)
        if text is None:
            continue
        is_tracked = path.resolve() in tracked
        lines = text.splitlines()

        if kind is not None:
            parsers = [_PARSERS[kind.format]]
            if kind.format == "yaml":
                parsers.append(_PARSERS["yaml-env-list"])
            for number, line in enumerate(lines, start=1):
                for parser in parsers:
                    for match in parser(line):
                        value = line[match.start:match.end]
                        verdict = classify(match.key, value)
                        if verdict is False:
                            continue
                        provider = verdict if isinstance(verdict, Provider) else None
                        marker = (path, number, match.start)
                        if marker in seen:
                            continue
                        seen.add(marker)
                        findings.append(Finding(
                            path, number, match.key, value, match.start, match.end, kind.format, kind.stack,
                            provider, rewritable=kind.format not in {"netrc"}, tracked=is_tracked,
                        ))

        # Unmistakable credentials anywhere in config or source files.
        for number, line in enumerate(lines, start=1):
            for provider in _STRONG_PROVIDERS:
                for match in provider.value_pattern.finditer(line):
                    if not _plausible_token(line, match.start(), match.group(0)):
                        continue
                    marker = (path, number, match.start())
                    if any(f.path == path and f.line == number and f.start <= match.start() < max(f.end, f.start + 1)
                           for f in findings):
                        continue
                    if marker in seen:
                        continue
                    seen.add(marker)
                    findings.append(Finding(
                        path, number, provider.id, match.group(0), match.start(), match.end(),
                        "source", kind.stack if kind else "source code", provider,
                        rewritable=False, tracked=is_tracked,
                    ))
    return findings
