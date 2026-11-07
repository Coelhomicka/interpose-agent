from __future__ import annotations

from typing import Protocol

from ..core.references import SecretReference
from ..models import ResolvedSecret, SecretMetadata


class SecretStoreError(RuntimeError):
    pass


class SecretNotFound(SecretStoreError):
    pass


class SecretValueError(SecretStoreError, ValueError):
    pass


def normalize_secret_value(value: str) -> str:
    """Strip surrounding whitespace from a value being stored.

    Pasted credentials often carry a stray space or newline. HTTP header values lose
    that whitespace in transit, so an upstream that echoes the credential would echo
    a form that differs from the stored one and slip past exact-match redaction.
    """
    cleaned = value.strip()
    if not cleaned:
        raise SecretValueError("secret value cannot be empty or only whitespace")
    return cleaned


class SecretStore(Protocol):
    def store(self, reference: SecretReference | str, value: str) -> SecretMetadata:
        raise NotImplementedError

    def resolve(self, reference: SecretReference | str) -> ResolvedSecret:
        raise NotImplementedError

    def delete(self, reference_or_id: SecretReference | str | int) -> bool:
        raise NotImplementedError

    def exists(self, reference: SecretReference | str) -> bool:
        raise NotImplementedError

    def list_metadata(self) -> list[SecretMetadata]:
        raise NotImplementedError

