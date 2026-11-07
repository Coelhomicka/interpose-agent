from __future__ import annotations

import hmac
import secrets

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from ..container import RuntimeContainer, create_container
from ..core.local_guard import browser_request_rejection, is_loopback_authority
from ..core.policies import PolicyDocument
from ..models import (
    AuditEntryResponse,
    PolicyCreateRequest,
    PolicyMetadataResponse,
    SecretCreateRequest,
    SecretMetadataResponse,
)
from ..secrets.base import SecretValueError


def _secret_response(metadata) -> SecretMetadataResponse:
    return SecretMetadataResponse(
        id=metadata.id,
        reference=metadata.reference,
        provider=metadata.provider,
        namespace=metadata.namespace,
        path=metadata.path,
        fingerprint=metadata.fingerprint,
        created_at=metadata.created_at,
        updated_at=metadata.updated_at,
    )


def _policy_response(record) -> PolicyMetadataResponse:
    return PolicyMetadataResponse(
        id=record.id,
        secret_reference=record.secret_reference,
        definition=record.definition,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


_UNAUTHENTICATED_PATHS = {"/health"}


def generate_admin_token() -> str:
    return secrets.token_urlsafe(32)


def create_app(container: RuntimeContainer | None = None, *, admin_token: str | None = None) -> FastAPI:
    """Build the admin API.

    Every route except ``/health`` requires ``Authorization: Bearer <admin_token>``.
    The token lives only in this process and the operator's terminal; it is never
    written to disk, where a same-user agent could read it. Without it, any local
    process could register a policy that allows its own host and then spend the
    secret through the broker.
    """
    runtime = container or create_container()
    token = admin_token or generate_admin_token()
    app = FastAPI(title="Interpose Admin API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.admin_token = token

    @app.middleware("http")
    async def guard(request: Request, call_next):
        rejection = browser_request_rejection(request.headers)
        if rejection is not None:
            return JSONResponse({"detail": rejection}, status_code=403)
        if not is_loopback_authority(request.headers.get("host", "")):
            return JSONResponse({"detail": "Host must be the loopback admin API"}, status_code=403)
        if request.url.path not in _UNAUTHENTICATED_PATHS:
            scheme, _, presented = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(presented.encode(), token.encode()):
                return JSONResponse(
                    {"detail": "admin token required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)

    def get_runtime() -> RuntimeContainer:
        return runtime

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/secrets", response_model=list[SecretMetadataResponse])
    def list_secrets(container: RuntimeContainer = Depends(get_runtime)) -> list[SecretMetadataResponse]:
        return [_secret_response(metadata) for metadata in container.secret_store.list_metadata()]

    @app.get("/secrets/{secret_id}", response_model=SecretMetadataResponse)
    def inspect_secret(secret_id: int, container: RuntimeContainer = Depends(get_runtime)) -> SecretMetadataResponse:
        metadata = next((item for item in container.secret_store.list_metadata() if item.id == secret_id), None)
        if metadata is None:
            raise HTTPException(status_code=404, detail="secret not found")
        return _secret_response(metadata)

    @app.post("/secrets", response_model=SecretMetadataResponse, status_code=201)
    def add_secret(
        payload: SecretCreateRequest,
        container: RuntimeContainer = Depends(get_runtime),
    ) -> SecretMetadataResponse:
        try:
            metadata = container.secret_store.store(payload.reference, payload.value)
        except SecretValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _secret_response(metadata)

    @app.delete("/secrets/{secret_id}", status_code=204)
    def delete_secret(secret_id: int, container: RuntimeContainer = Depends(get_runtime)) -> None:
        if not container.secret_store.delete(secret_id):
            raise HTTPException(status_code=404, detail="secret not found")

    @app.get("/policies", response_model=list[PolicyMetadataResponse])
    def list_policies(container: RuntimeContainer = Depends(get_runtime)) -> list[PolicyMetadataResponse]:
        return [_policy_response(record) for record in container.policy_repository.list()]

    @app.post("/policies", response_model=PolicyMetadataResponse, status_code=201)
    def add_policy(
        payload: PolicyCreateRequest,
        container: RuntimeContainer = Depends(get_runtime),
    ) -> PolicyMetadataResponse:
        document = PolicyDocument.from_yaml(payload.definition)
        record = container.policy_repository.store(document)
        return _policy_response(record)

    @app.delete("/policies/{policy_id}", status_code=204)
    def delete_policy(policy_id: int, container: RuntimeContainer = Depends(get_runtime)) -> None:
        if not container.policy_repository.delete(policy_id):
            raise HTTPException(status_code=404, detail="policy not found")

    @app.get("/audit", response_model=list[AuditEntryResponse])
    def list_audit(container: RuntimeContainer = Depends(get_runtime)) -> list[AuditEntryResponse]:
        return container.audit_logger.list()

    return app

