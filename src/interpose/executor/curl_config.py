"""Move the arguments that carry secret references out of curl's argv.

Arguments are visible to every process of the same user (``ps``, Task Manager,
``/proc/<pid>/cmdline``). After resolution, an argument holding a reference holds
the plaintext, so those arguments are handed to curl through ``--config -`` on
standard input instead; the command line keeps only arguments without secrets.

The config syntax is curl's own: ``header = "Authorization: Bearer …"``.
Backslashes inside quoted values are not reliably round-tripped by curl's parser,
so a value containing one is refused rather than sent altered.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..core.references import collect_secret_references

# Short options that take a value, and the long name used for those that may
# legitimately carry a credential.
_SHORT_WITH_VALUE = set("AbcCDdeEFHKmoQrTtuUwXxYyz")
_SHORT_TO_LONG = {
    "H": "header",
    "d": "data",
    "u": "user",
    "b": "cookie",
    "F": "form",
    "e": "referer",
    "A": "user-agent",
}
_LONG_WITH_SECRET_VALUE = {
    "header",
    "data",
    "data-raw",
    "data-binary",
    "data-ascii",
    "data-urlencode",
    "json",
    "user",
    "cookie",
    "form",
    "form-string",
    "oauth2-bearer",
    "url-query",
    "referer",
    "user-agent",
    "proxy-header",
}
# Long options that take no value, so a following URL is not mistaken for theirs.
_LONG_FLAGS = {
    "silent", "show-error", "verbose", "include", "fail", "fail-with-body", "compressed",
    "head", "get", "globoff", "no-progress-meter", "http1.1", "http2", "http3", "ipv4", "ipv6",
    "insecure", "no-buffer", "no-keepalive", "path-as-is", "raw", "remote-name", "remote-header-name",
    "trace-time", "no-styled-output",
}


class CurlConfigError(ValueError):
    pass


def _has_reference(token: str) -> bool:
    return bool(collect_secret_references(token))


def _quote(value: str) -> str:
    if "\\" in value:
        raise CurlConfigError("values containing a backslash cannot be passed to curl safely")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CurlConfigError("values containing control characters cannot be passed to curl")
    return '"' + value.replace('"', '\\"') + '"'


def _reads_stdin(token: str) -> bool:
    return token == "-" or "@-" in token


def split_secret_arguments(command: Sequence[str]) -> tuple[list[str], str]:
    """Return ``(argv, config)``: argv without any reference, config with the rest.

    ``config`` is empty when no argument carries a reference, and ``argv`` then
    equals ``command``. Fails closed on any shape it does not understand.
    """
    argv = [command[0]]
    lines: list[str] = []
    tokens = list(command[1:])
    moved = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None

        if token.startswith("--"):
            name = token[2:]
            if _has_reference(token):
                raise CurlConfigError(f"a secret reference cannot be part of option {token.split('=')[0]}")
            if name in _LONG_FLAGS:
                argv.append(token)
                index += 1
                continue
            if nxt is not None and _has_reference(nxt):
                if name not in _LONG_WITH_SECRET_VALUE:
                    raise CurlConfigError(f"option {token} cannot carry a secret reference")
                lines.append(f"{name} = {_quote(nxt)}")
                moved = True
            else:
                argv.append(token)
                if nxt is not None:
                    argv.append(nxt)
            index += 2
            continue

        if token.startswith("-") and len(token) > 1:
            cluster = token[1:]
            position = next((i for i, flag in enumerate(cluster) if flag in _SHORT_WITH_VALUE), None)
            if position is None:
                if _has_reference(token):
                    raise CurlConfigError("a secret reference cannot be part of a flag")
                argv.append(token)
                index += 1
                continue
            flag = cluster[position]
            attached = cluster[position + 1:]
            value = attached if attached else nxt
            consumed = 1 if attached else 2
            if value is not None and _has_reference(value):
                if flag not in _SHORT_TO_LONG:
                    raise CurlConfigError(f"option -{flag} cannot carry a secret reference")
                if position:
                    argv.append("-" + cluster[:position])
                lines.append(f"{_SHORT_TO_LONG[flag]} = {_quote(value)}")
                moved = True
            else:
                argv.append(token)
                if not attached and nxt is not None:
                    argv.append(nxt)
            index += consumed
            continue

        if _has_reference(token):
            lines.append(f"url = {_quote(token)}")
            moved = True
        else:
            argv.append(token)
        index += 1

    if not moved:
        return list(command), ""
    if any(_reads_stdin(token) for token in argv[1:]):
        raise CurlConfigError("curl reads its secrets from standard input here; '-' and '@-' are not available")
    # Right after the executable, so no preceding option can take it as its value.
    return [argv[0], "--config", "-", *argv[1:]], "\n".join(lines) + "\n"
