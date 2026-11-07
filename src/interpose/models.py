from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecretCreateRequest(BaseModel):
    reference: str = Field(min_length=1)
    value: str = Field(min_length=1)


class PolicyCreateRequest(BaseModel):
    definition: str = Field(min_length=1)


class SecretMetadataResponse(BaseModel):
    id: int
    reference: str
    provider: str
    namespace: str
    path: str
    fingerprint: str
    created_at: datetime
    updated_at: datetime


class PolicyMetadataResponse(BaseModel):
    id: int
    secret_reference: str
    created_at: datetime
    updated_at: datetime
    definition: str


class AuditEntryResponse(BaseModel):
    id: int
    timestamp: datetime
    session: str
    agent: str
    secret_reference: str
    destination: str
    action: str
    policy_result: str
    status: str
    duration_ms: int
    details: dict[str, Any]


@dataclass(frozen=True)
class DestinationContext:
    host: str
    method: str
    scheme: str = "https"
    url: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    secret_reference: str
    destination: str
    method: str


@dataclass(frozen=True)
class SecretMetadata:
    id: int
    reference: str
    provider: str
    namespace: str
    path: str
    fingerprint: str
    created_at: datetime
    updated_at: datetime
    scope: str = "global"


@dataclass(frozen=True)
class ResolvedSecret:
    metadata: SecretMetadata
    value: str


@dataclass(frozen=True)
class SubstitutionResult:
    value: Any
    references: tuple[str, ...]
    resolutions: tuple[ResolvedSecret, ...]


@dataclass(frozen=True)
class ExecutionResult:
    command: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    allowed: bool
    policy_result: str
    destination: str
    duration_ms: int


@dataclass(frozen=True)
class PolicyRecord:
    id: int
    secret_reference: str
    definition: str
    created_at: datetime
    updated_at: datetime
    scope: str = "global"
