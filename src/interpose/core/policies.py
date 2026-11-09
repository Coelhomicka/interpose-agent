from __future__ import annotations

import fnmatch
import ipaddress
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..models import DestinationContext, PolicyDecision, PolicyRecord
from .references import SecretReference, normalize_secret_reference
from .scopes import GLOBAL_SCOPE, ScopeContext, validate_scope


class PolicyError(ValueError):
    pass


class HostGroup(BaseModel):
    hosts: list[str] = Field(default_factory=list)


def host_matches(host: str, pattern: str) -> bool:
    """Whether ``host`` (``name[:port]``, lower-case) is covered by an allow pattern.

    Patterns are an exact authority (``api.example.com``, ``localhost:8001``), a
    subdomain wildcard (``*.example.com``, which covers ``a.example.com`` and
    ``a.b.example.com`` but not ``example.com`` or ``evilexample.com``), or ``*``.
    A ``*`` anywhere else matches nothing: glob semantics would let ``api.*`` or
    ``*example.com`` cover hosts the operator never meant to trust.
    """
    host = host.lower()
    pattern = pattern.strip().lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return "*" not in suffix and host.endswith(suffix) and len(host) > len(suffix)
    return "*" not in pattern and host == pattern


def _host_denied(host: str, pattern: str) -> bool:
    # Deny patterns keep full glob semantics: matching too much only blocks more.
    pattern = pattern.strip().lower()
    return host_matches(host, pattern) or fnmatch.fnmatchcase(host.lower(), pattern)


INJECTION_KINDS = ("header", "query", "form")


@dataclass(frozen=True)
class RequestLocation:
    """Where a reference was found in a request: ``kind`` plus the field name.

    ``kind`` is one of ``header``, ``query``, ``form``, or ``body``. Body
    occurrences carry no name and never match an injection slot.
    """

    kind: str
    name: str | None = None

    def matches(self, other: RequestLocation) -> bool:
        if self.kind != other.kind or self.name is None or other.name is None:
            return False
        if self.kind == "header":
            return self.name.lower() == other.name.lower()
        return self.name == other.name

    def describe(self) -> str:
        return f"{self.kind} {self.name!r}" if self.name else self.kind


# Applied when a policy does not declare ``inject``. Credentials normally travel in
# these headers; anything else (bodies, query strings, arbitrary headers) is a
# place the value could be echoed back or published, so it must be opted into.
DEFAULT_INJECTION_SLOTS: tuple[RequestLocation, ...] = (
    RequestLocation(kind="header", name="authorization"),
    RequestLocation(kind="header", name="x-api-key"),
)


class InjectionSlot(BaseModel):
    """One place in an outbound request where the broker may substitute this secret.

    Exactly one of ``header``, ``query`` or ``form`` is set. Header names match
    case-insensitively; query and form field names match exactly.
    """

    header: str | None = None
    query: str | None = None
    form: str | None = None

    @model_validator(mode="after")
    def validate_single_location(self) -> InjectionSlot:
        populated = [kind for kind in INJECTION_KINDS if getattr(self, kind)]
        if len(populated) != 1:
            raise ValueError("an inject entry must set exactly one of: header, query, form")
        return self

    def location(self) -> RequestLocation:
        for kind in INJECTION_KINDS:
            name = getattr(self, kind)
            if name:
                return RequestLocation(kind=kind, name=name.strip())
        raise AssertionError("unreachable: validated slot has no location")


class PolicyDocument(BaseModel):
    secret: str = Field(min_length=1)
    allow: HostGroup | None = None
    deny: HostGroup | None = None
    methods: list[str] | None = None
    schemes: list[str] | None = None
    paths: list[str] | None = None
    inject: list[InjectionSlot] | None = None
    allow_exec: bool = False

    @field_validator("allow")
    @classmethod
    def validate_allow_hosts(cls, value: HostGroup | None) -> HostGroup | None:
        if value is None:
            return None
        for pattern in value.hosts:
            stripped = pattern.strip()
            if "*" in stripped and stripped != "*" and not (
                stripped.startswith("*.") and "*" not in stripped[1:]
            ):
                raise ValueError(
                    f"allow host {pattern!r}: '*' is only allowed alone or as the leading label (*.example.com)"
                )
        return value

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        if any(not value.startswith("/") for value in values):
            raise ValueError("policy paths must start with '/'")
        return values

    @field_validator("schemes")
    @classmethod
    def validate_schemes(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        normalized = [scheme.lower() for scheme in values]
        if any(scheme not in {"http", "https"} for scheme in normalized):
            raise ValueError("policy schemes must be http or https")
        return normalized

    @classmethod
    def from_yaml(cls, source: str) -> PolicyDocument:
        try:
            payload = yaml.safe_load(source)
        except Exception as exc:  # pragma: no cover - defensive
            raise PolicyError(f"invalid policy yaml: {exc}") from exc
        if not isinstance(payload, dict):
            raise PolicyError("policy document must be a mapping")
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            raise PolicyError(str(exc)) from exc

    def normalized_methods(self) -> tuple[str, ...]:
        return tuple(method.upper() for method in (self.methods or []))

    def normalized_secret(self) -> str:
        return normalize_secret_reference(self.secret)

    def normalized_schemes(self) -> tuple[str, ...]:
        return tuple(self.schemes or [])

    def injection_slots(self) -> tuple[RequestLocation, ...]:
        if self.inject is None:
            return DEFAULT_INJECTION_SLOTS
        return tuple(slot.location() for slot in self.inject)


def _is_loopback_destination(host: str) -> bool:
    try:
        hostname = urlsplit(f"//{host}").hostname
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class SQLitePolicyRepository:
    def __init__(self, database_path: Path | str) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

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
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(policies)").fetchall()}
            legacy = bool(columns) and "scope" not in columns
            if legacy:
                connection.execute("ALTER TABLE policies RENAME TO policies_unscoped")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL DEFAULT 'global',
                    secret_reference TEXT NOT NULL,
                    definition TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (scope, secret_reference)
                )
                """
            )
            if legacy:
                connection.execute(
                    """
                    INSERT INTO policies (id, scope, secret_reference, definition, created_at, updated_at)
                    SELECT id, 'global', secret_reference, definition, created_at, updated_at
                    FROM policies_unscoped
                    """
                )
                connection.execute("DROP TABLE policies_unscoped")

    @staticmethod
    def _from_row(row: sqlite3.Row) -> PolicyRecord:
        return PolicyRecord(
            id=row["id"],
            secret_reference=row["secret_reference"],
            definition=row["definition"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            scope=row["scope"],
        )

    def store(self, document: PolicyDocument, *, scope: str = GLOBAL_SCOPE) -> PolicyRecord:
        scope = validate_scope(scope)
        now = datetime.now(UTC).isoformat()
        secret_reference = document.normalized_secret()
        definition = document.model_dump_json()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM policies WHERE scope = ? AND secret_reference = ?",
                (scope, secret_reference),
            ).fetchone()
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO policies (scope, secret_reference, definition, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scope, secret_reference, definition, now, now),
                )
                policy_id = int(cursor.lastrowid)
                created_at = now
            else:
                policy_id = int(existing["id"])
                created_at = existing["created_at"]
                connection.execute(
                    "UPDATE policies SET definition = ?, updated_at = ? WHERE id = ?",
                    (definition, now, policy_id),
                )
        return PolicyRecord(
            id=policy_id,
            secret_reference=secret_reference,
            definition=definition,
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(now),
            scope=scope,
        )

    def list(self, scope: str | None = None) -> list[PolicyRecord]:
        with self._connect() as connection:
            if scope is None:
                rows = connection.execute("SELECT * FROM policies ORDER BY id ASC").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM policies WHERE scope = ? ORDER BY id ASC",
                    (validate_scope(scope),),
                ).fetchall()
        return [self._from_row(row) for row in rows]

    def get(self, policy_id: int) -> PolicyRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        return self._from_row(row) if row else None

    def get_by_secret(
        self,
        secret_reference: str,
        *,
        scopes: Iterable[str] = (GLOBAL_SCOPE,),
    ) -> PolicyRecord | None:
        """The first policy for ``secret_reference`` along the scope chain."""
        with self._connect() as connection:
            for scope in scopes:
                row = connection.execute(
                    "SELECT * FROM policies WHERE scope = ? AND secret_reference = ?",
                    (scope, secret_reference),
                ).fetchone()
                if row is not None:
                    return self._from_row(row)
        return None

    def purge_scope(self, scope: str) -> int:
        """Delete every policy in ``scope``; returns how many were removed."""
        scope = validate_scope(scope)
        if scope == GLOBAL_SCOPE:
            raise ValueError("refusing to purge the global scope")
        with self._connect() as connection:
            return connection.execute("DELETE FROM policies WHERE scope = ?", (scope,)).rowcount

    def delete(self, policy_id: int) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
            return cursor.rowcount > 0


class PolicyEngine:
    """Evaluates the policy in effect for a reference along the scope chain.

    A project policy shadows the global one for the same reference. Scopes organize
    configuration; they are not an isolation boundary against code running as the
    same user, which can address any project's route (or the global one). The hosts
    a secret can reach are therefore the union of every policy written for it, and
    a project policy that is narrower than the global one does not contain anything.
    See docs/en/THREAT_MODEL.md.
    """

    def __init__(self, repository: SQLitePolicyRepository, context: ScopeContext | None = None) -> None:
        self._repository = repository
        self._context = context or ScopeContext()

    def effective_policy(self, secret_reference: SecretReference) -> PolicyRecord | None:
        return self._repository.get_by_secret(secret_reference.canonical, scopes=self._context.chain())

    def _document(self, secret_reference: SecretReference) -> PolicyDocument | None:
        record = self.effective_policy(secret_reference)
        if record is None:
            return None
        return PolicyDocument.from_yaml(record.definition)

    @staticmethod
    def _deny(secret_reference: SecretReference, destination: DestinationContext, reason: str) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason=reason,
            secret_reference=secret_reference.canonical,
            destination=destination.host,
            method=destination.method.upper(),
        )

    def evaluate(
        self,
        secret_reference: SecretReference,
        destination: DestinationContext,
        *,
        location: RequestLocation | None = None,
    ) -> PolicyDecision:
        """Decide whether ``secret_reference`` may be resolved for ``destination``.

        When ``location`` is given, the reference must also sit in one of the
        policy's injection slots. A reference anywhere else is denied: a body or an
        arbitrary field is a place an allowed host can echo or publish the value.
        """
        try:
            document = self._document(secret_reference)
        except PolicyError:
            # A policy stored before a validation rule tightened fails closed.
            return self._deny(secret_reference, destination, "stored policy is no longer valid; edit it")
        if document is None:
            return self._deny(secret_reference, destination, "No policy registered for secret reference")

        requested_method = destination.method.upper()
        requested_scheme = destination.scheme.lower()
        allowed_schemes = document.normalized_schemes()
        if allowed_schemes and requested_scheme not in allowed_schemes:
            return self._deny(secret_reference, destination, f"scheme {requested_scheme} is not allowed")
        if not allowed_schemes and requested_scheme != "https" and not _is_loopback_destination(destination.host):
            return self._deny(secret_reference, destination, "insecure HTTP requires an explicit policy scheme")

        allowed_methods = document.normalized_methods()
        if requested_method == "EXEC" and "EXEC" not in allowed_methods:
            # Handing the plaintext to an arbitrary executable is never implied by an
            # empty method list; the operator has to name it.
            return self._deny(secret_reference, destination, "method EXEC must be listed explicitly")
        if allowed_methods and requested_method not in allowed_methods:
            return self._deny(secret_reference, destination, f"method {requested_method} is not allowed")

        host = destination.host.lower()
        deny_hosts = [pattern.lower() for pattern in document.deny.hosts] if document.deny else []
        for pattern in deny_hosts:
            if _host_denied(host, pattern):
                return self._deny(
                    secret_reference, destination, f"destination {destination.host} denied by pattern {pattern}"
                )

        allow_hosts = [pattern.lower() for pattern in document.allow.hosts] if document.allow else []
        if not allow_hosts:
            return self._deny(secret_reference, destination, "policy does not define any allowed hosts")
        if not any(host_matches(host, pattern) for pattern in allow_hosts):
            return self._deny(secret_reference, destination, f"destination {destination.host} is not in allow list")

        if document.paths is not None:
            requested_path = destination.path or "/"
            if not any(fnmatch.fnmatchcase(requested_path, pattern) for pattern in document.paths):
                return self._deny(secret_reference, destination, f"path {requested_path} is not in allow list")

        if location is not None and not any(slot.matches(location) for slot in document.injection_slots()):
            return self._deny(
                secret_reference,
                destination,
                f"reference is not allowed in {location.describe()}; "
                "declare an inject slot in the policy to permit it",
            )

        return PolicyDecision(
            allowed=True,
            reason="allowed",
            secret_reference=secret_reference.canonical,
            destination=destination.host,
            method=requested_method,
        )

    def allows_exec(self, secret_reference: SecretReference) -> bool:
        try:
            document = self._document(secret_reference)
        except PolicyError:
            return False
        return bool(document and document.allow_exec)
