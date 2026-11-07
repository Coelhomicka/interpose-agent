from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.references import SecretReference
from ..core.scopes import GLOBAL_SCOPE, ScopeContext, validate_scope
from ..models import ResolvedSecret, SecretMetadata
from .base import SecretNotFound, SecretStore, normalize_secret_value


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_reference(reference: SecretReference | str) -> SecretReference:
    return reference if isinstance(reference, SecretReference) else SecretReference.parse(reference)


FINGERPRINT_PREFIX = "hmac-sha256:"


def associated_data(scope: str, reference: SecretReference) -> bytes:
    """AES-GCM associated data binding a ciphertext to its scope and reference.

    Global records keep the bare canonical reference so vaults written before
    scopes existed still decrypt. Project records include the scope, so a row
    copied into another scope (or another project) fails authentication instead
    of decrypting under the wrong context.
    """
    if scope == GLOBAL_SCOPE:
        return reference.canonical.encode("utf-8")
    return f"{scope}|{reference.canonical}".encode()


class EncryptedLocalSecretStore(SecretStore):
    def __init__(self, database_path: Path | str, master_key: bytes) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._aesgcm = AESGCM(hashlib.sha256(master_key).digest())
        # A keyed fingerprint: equality and audit correlation still work, but the
        # stored and listed value is no longer an offline oracle for guessing
        # low-entropy secrets, as a bare SHA-256 of the plaintext was.
        self._fingerprint_key = hmac.new(master_key, b"interpose/fingerprint/v1", hashlib.sha256).digest()
        self._initialize()
        self._migrate_unkeyed_fingerprints()

    def fingerprint(self, value: str) -> str:
        digest = hmac.new(self._fingerprint_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{FINGERPRINT_PREFIX}{digest}"

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        try:
            # sqlite3's connection context manager governs the transaction, not the
            # handle: without the explicit close the file stays open until GC, which
            # leaks descriptors and keeps the database locked on Windows.
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(secrets)").fetchall()}
            if columns and "scope" not in columns:
                # Pre-scope vault: one row per reference. Rebuild with a scope column
                # and a (scope, reference) key; every existing row becomes global.
                connection.execute("ALTER TABLE secrets RENAME TO secrets_unscoped")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL DEFAULT 'global',
                    reference TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    secret_path TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (scope, reference)
                )
                """
            )
            if columns and "scope" not in columns:
                connection.execute(
                    """
                    INSERT INTO secrets (
                        id, scope, reference, provider, namespace, secret_path,
                        ciphertext, nonce, fingerprint, created_at, updated_at
                    )
                    SELECT id, 'global', reference, provider, namespace, secret_path,
                           ciphertext, nonce, fingerprint, created_at, updated_at
                    FROM secrets_unscoped
                    """
                )
                connection.execute("DROP TABLE secrets_unscoped")

    def _migrate_unkeyed_fingerprints(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, scope, reference, ciphertext, nonce FROM secrets WHERE fingerprint NOT LIKE ?",
                (f"{FINGERPRINT_PREFIX}%",),
            ).fetchall()
            for row in rows:
                plaintext = self._aesgcm.decrypt(
                    row["nonce"],
                    row["ciphertext"],
                    associated_data(row["scope"], SecretReference.parse(row["reference"])),
                )
                connection.execute(
                    "UPDATE secrets SET fingerprint = ? WHERE id = ?",
                    (self.fingerprint(plaintext.decode("utf-8")), row["id"]),
                )

    def _metadata_from_row(self, row: sqlite3.Row) -> SecretMetadata:
        return SecretMetadata(
            id=row["id"],
            reference=row["reference"],
            provider=row["provider"],
            namespace=row["namespace"],
            path=row["secret_path"],
            fingerprint=row["fingerprint"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            scope=row["scope"],
        )

    def store(
        self,
        reference: SecretReference | str,
        value: str,
        *,
        scope: str = GLOBAL_SCOPE,
    ) -> SecretMetadata:
        ref = _as_reference(reference)
        scope = validate_scope(scope)
        value = normalize_secret_value(value)
        now = _utc_now().isoformat()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, value.encode("utf-8"), associated_data(scope, ref))
        fingerprint = self.fingerprint(value)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM secrets WHERE scope = ? AND reference = ?",
                (scope, ref.canonical),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO secrets (
                        scope, reference, provider, namespace, secret_path,
                        ciphertext, nonce, fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scope, ref.canonical, ref.provider, ref.namespace, ref.path,
                     ciphertext, nonce, fingerprint, now, now),
                )
                secret_id = int(cursor.lastrowid)
                created_at = now
            else:
                secret_id = int(existing["id"])
                created_at = existing["created_at"]
                connection.execute(
                    """
                    UPDATE secrets
                    SET provider = ?, namespace = ?, secret_path = ?, ciphertext = ?,
                        nonce = ?, fingerprint = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (ref.provider, ref.namespace, ref.path, ciphertext, nonce, fingerprint, now, secret_id),
                )
        return SecretMetadata(
            id=secret_id,
            reference=ref.canonical,
            provider=ref.provider,
            namespace=ref.namespace,
            path=ref.path,
            fingerprint=fingerprint,
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(now),
            scope=scope,
        )

    def _find_row(self, ref: SecretReference, scopes: Iterable[str]) -> sqlite3.Row | None:
        with self._connect() as connection:
            for scope in scopes:
                row = connection.execute(
                    "SELECT * FROM secrets WHERE scope = ? AND reference = ?",
                    (scope, ref.canonical),
                ).fetchone()
                if row is not None:
                    return row
        return None

    def resolve(
        self,
        reference: SecretReference | str,
        *,
        scopes: Iterable[str] = (GLOBAL_SCOPE,),
    ) -> ResolvedSecret:
        """Decrypt the first record for ``reference`` along the scope chain."""
        ref = _as_reference(reference)
        row = self._find_row(ref, scopes)
        if row is None:
            raise SecretNotFound(f"secret not found: {ref.canonical}")
        plaintext = self._aesgcm.decrypt(
            row["nonce"],
            row["ciphertext"],
            associated_data(row["scope"], ref),
        ).decode("utf-8")
        return ResolvedSecret(metadata=self._metadata_from_row(row), value=plaintext)

    def delete(
        self,
        reference_or_id: SecretReference | str | int,
        *,
        scope: str = GLOBAL_SCOPE,
    ) -> bool:
        if isinstance(reference_or_id, int):
            query = "DELETE FROM secrets WHERE id = ?"
            params: tuple = (reference_or_id,)
        else:
            query = "DELETE FROM secrets WHERE scope = ? AND reference = ?"
            params = (validate_scope(scope), _as_reference(reference_or_id).canonical)
        with self._connect() as connection:
            cursor = connection.execute(query, params)
            return cursor.rowcount > 0

    def exists(
        self,
        reference: SecretReference | str,
        *,
        scopes: Iterable[str] = (GLOBAL_SCOPE,),
    ) -> bool:
        return self._find_row(_as_reference(reference), scopes) is not None

    def list_metadata(self, scope: str | None = None) -> list[SecretMetadata]:
        with self._connect() as connection:
            if scope is None:
                rows = connection.execute("SELECT * FROM secrets ORDER BY reference ASC, scope ASC").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM secrets WHERE scope = ? ORDER BY reference ASC",
                    (validate_scope(scope),),
                ).fetchall()
        return [self._metadata_from_row(row) for row in rows]


class ScopedSecretStore:
    """The vault as seen by one runtime process: resolution follows the active
    scope chain, and writes default to the global scope unless told otherwise."""

    def __init__(self, store: EncryptedLocalSecretStore, context: ScopeContext) -> None:
        self.backend = store
        self.context = context

    def store(self, reference: SecretReference | str, value: str, *, scope: str = GLOBAL_SCOPE) -> SecretMetadata:
        return self.backend.store(reference, value, scope=scope)

    def resolve(self, reference: SecretReference | str) -> ResolvedSecret:
        return self.backend.resolve(reference, scopes=self.context.chain())

    def exists(self, reference: SecretReference | str) -> bool:
        return self.backend.exists(reference, scopes=self.context.chain())

    def delete(self, reference_or_id: SecretReference | str | int, *, scope: str = GLOBAL_SCOPE) -> bool:
        return self.backend.delete(reference_or_id, scope=scope)

    def list_metadata(self, scope: str | None = None) -> list[SecretMetadata]:
        return self.backend.list_metadata(scope)
