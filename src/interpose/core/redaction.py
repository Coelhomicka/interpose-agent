from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

# Variants shorter than this are not redacted on their own: replacing every
# occurrence of a two-character string would corrupt responses without adding
# meaningful protection.
_MIN_VARIANT_LENGTH = 6
# Fragments of a value base64-encoded inside a longer string are only partial
# matches, so they need more length before they are distinctive.
_MIN_EMBEDDED_LENGTH = 8


def _embedded_base64(raw: bytes) -> set[str]:
    """The characters that encode ``raw`` wherever it sits inside a base64 stream.

    ``Basic base64(user:token)`` puts the token at an arbitrary byte offset, so the
    standalone encoding never appears. For each of the three alignments, keep only
    the characters determined by ``raw`` alone.
    """
    fragments: set[str] = set()
    for offset in range(3):
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encode(b"\0" * offset + raw).decode("ascii").rstrip("=")
            if (offset + len(raw)) % 3:
                encoded = encoded[:-1]  # last character mixes with whatever follows
            # Drop leading characters that also carry bits of the preceding byte(s).
            encoded = encoded[(offset * 4 + 2) // 3:]
            if len(encoded) >= _MIN_EMBEDDED_LENGTH:
                fragments.add(encoded)
    return fragments


def redaction_variants(secret_value: str) -> set[str]:
    """Forms in which an upstream commonly reflects a credential.

    Covers the value as sent and trimmed, percent-encoded, JSON-escaped, hex, and
    base64 (standalone, URL-safe, and embedded at any alignment, as in Basic
    authentication). Matching is case-insensitive, which also covers upper-case hex
    and an upstream that changes the case of what it echoes.

    Redaction is defense in depth. The guarantee comes from policy: a secret is only
    sent to approved hosts, in approved fields. An approved host that deliberately
    transforms and returns the value (encrypts it, splits it) can still defeat this.
    """
    variants = {secret_value}
    stripped = secret_value.strip()
    for value in {secret_value, stripped}:
        raw = value.encode("utf-8")
        variants.add(value)
        variants.add(quote(value, safe=""))
        variants.add(quote_plus(value))
        escaped = json.dumps(value)[1:-1]
        variants.add(escaped)
        variants.add(escaped.replace("/", "\\/"))
        variants.add(json.dumps(value, ensure_ascii=False)[1:-1])
        variants.add(raw.hex())
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encode(raw).decode("ascii")
            variants.add(encoded)
            variants.add(encoded.rstrip("="))
        variants.update(_embedded_base64(raw))
    return {variant for variant in variants if len(variant) >= _MIN_VARIANT_LENGTH or variant == secret_value}


@dataclass
class SecretRedactionEngine:
    _values: set[str] = field(default_factory=set)
    _fingerprints: set[str] = field(default_factory=set)
    _text_pattern: re.Pattern[str] | None = field(default=None, repr=False)
    _bytes_pattern: re.Pattern[bytes] | None = field(default=None, repr=False)

    def register(self, secret_value: str) -> str:
        fingerprint = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
        new_values = redaction_variants(secret_value) - self._values
        if new_values:
            self._values.update(new_values)
            self._text_pattern = None
            self._bytes_pattern = None
        self._fingerprints.add(fingerprint)
        return fingerprint

    def register_many(self, secrets: Iterable[str]) -> tuple[str, ...]:
        return tuple(self.register(secret) for secret in secrets)

    @property
    def fingerprints(self) -> tuple[str, ...]:
        return tuple(sorted(self._fingerprints))

    def _ordered(self) -> list[str]:
        # Longest first, so the regex alternation prefers a whole value over any
        # shorter variant inside it.
        return sorted((value for value in self._values if value), key=len, reverse=True)

    def _text(self) -> re.Pattern[str] | None:
        if self._text_pattern is None and self._values:
            self._text_pattern = re.compile(
                "|".join(re.escape(value) for value in self._ordered()), re.IGNORECASE
            )
        return self._text_pattern

    def _bytes(self) -> re.Pattern[bytes] | None:
        if self._bytes_pattern is None and self._values:
            self._bytes_pattern = re.compile(
                b"|".join(re.escape(value.encode("utf-8")) for value in self._ordered()), re.IGNORECASE
            )
        return self._bytes_pattern

    def redact(self, text: str) -> str:
        pattern = self._text()
        return pattern.sub("[REDACTED]", text) if pattern else text

    def redact_bytes(self, payload: bytes) -> bytes:
        # Work on bytes directly: decoding first would let a single invalid byte
        # anywhere in the payload skip redaction entirely.
        pattern = self._bytes()
        return pattern.sub(b"[REDACTED]", payload) if pattern else payload
