from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

# Variants shorter than this are not redacted on their own: replacing every
# occurrence of a two-character string would corrupt responses without adding
# meaningful protection.
_MIN_VARIANT_LENGTH = 6


def redaction_variants(secret_value: str) -> set[str]:
    """Forms in which an upstream commonly reflects a credential.

    Exact match alone misses a value that was trimmed on the way (HTTP header
    values lose surrounding whitespace), percent-encoded in a URL the upstream
    echoes, or base64-encoded as in Basic authentication.
    """
    variants = {secret_value}
    stripped = secret_value.strip()
    for value in {secret_value, stripped}:
        variants.add(value)
        variants.add(quote(value, safe=""))
        variants.add(quote_plus(value))
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        variants.add(encoded)
        variants.add(encoded.rstrip("="))
    return {variant for variant in variants if len(variant) >= _MIN_VARIANT_LENGTH or variant == secret_value}


@dataclass
class SecretRedactionEngine:
    _values: set[str] = field(default_factory=set)
    _fingerprints: set[str] = field(default_factory=set)

    def register(self, secret_value: str) -> str:
        fingerprint = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
        self._values.update(redaction_variants(secret_value))
        self._fingerprints.add(fingerprint)
        return fingerprint

    def register_many(self, secrets: Iterable[str]) -> tuple[str, ...]:
        return tuple(self.register(secret) for secret in secrets)

    @property
    def fingerprints(self) -> tuple[str, ...]:
        return tuple(sorted(self._fingerprints))

    def _ordered(self) -> list[str]:
        # Longest first, so a value is replaced before any shorter variant inside it.
        return sorted((value for value in self._values if value), key=len, reverse=True)

    def redact(self, text: str) -> str:
        redacted = text
        for secret_value in self._ordered():
            redacted = redacted.replace(secret_value, "[REDACTED]")
        return redacted

    def redact_bytes(self, payload: bytes) -> bytes:
        # Work on bytes directly: decoding first would let a single invalid byte
        # anywhere in the payload skip redaction entirely.
        redacted = payload
        for secret_value in self._ordered():
            redacted = redacted.replace(secret_value.encode("utf-8"), b"[REDACTED]")
        return redacted
