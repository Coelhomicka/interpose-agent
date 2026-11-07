"""The local configuration dashboard.

Modeled on the .NET Aspire dashboard: ``interpose up`` prints and opens a URL
carrying a one-time login token. The token is exchanged for an HttpOnly,
SameSite=Strict session cookie and then stops working, so a copy of the URL left
in shell history or browser history cannot be replayed.

The dashboard is the control plane, which makes it the most valuable thing on the
machine for an agent to reach. Therefore:

* no route returns a secret value; values are write-only;
* the ``Host`` must be loopback (DNS rebinding) and any ``Origin`` must be the
  dashboard's own (CSRF);
* every mutation also requires a per-session CSRF token in a custom header;
* responses forbid framing and inline script, and are never cached.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, ValidationError

from ..container import RuntimeContainer
from ..core.local_guard import is_loopback_authority
from ..core.policies import PolicyDocument, PolicyError
from ..core.references import SecretReference, SecretReferenceError, normalize_secret_reference
from ..core.scopes import GLOBAL_SCOPE, ScopeError, project_scope
from ..secrets.base import SecretValueError

SESSION_COOKIE = "interpose_session"
CSRF_HEADER = "x-interpose-csrf"
_STATIC_FILES = {
    "/app.js": "application/javascript; charset=utf-8",
    "/app.css": "text/css; charset=utf-8",
}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_LOGIN_REQUIRED_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Interpose</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/app.css"></head>
<body class="gate"><main class="gate-card">
<h1>Interpose</h1>
<p>{message}</p>
<p>Open the link printed by <code>interpose up</code> in your terminal.
Each link works once; restart <code>interpose up</code> for a new one.</p>
</main></body></html>"""


@dataclass
class DashboardAuth:
    login_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    login_token_used: bool = False
    sessions: dict[str, str] = field(default_factory=dict)  # session id -> csrf token

    def redeem(self, presented: str) -> str | None:
        if self.login_token_used or not hmac.compare_digest(presented.encode(), self.login_token.encode()):
            return None
        self.login_token_used = True
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = secrets.token_urlsafe(32)
        return session_id

    def csrf_for(self, session_id: str | None) -> str | None:
        if not session_id:
            return None
        return self.sessions.get(session_id)


@dataclass(frozen=True)
class DashboardContext:
    """Facts about this ``interpose up`` process shown in the dashboard."""

    working_directory: Path
    proxy_url: str


class SecretWrite(BaseModel):
    scope: Literal["global", "project"]
    reference: str = Field(min_length=1, max_length=512)
    value: str = Field(min_length=1, max_length=65536)


class InjectWrite(BaseModel):
    kind: Literal["header", "query", "form"]
    name: str = Field(min_length=1, max_length=128)


class PolicyWrite(BaseModel):
    scope: Literal["global", "project"]
    secret: str = Field(min_length=1, max_length=512)
    hosts: list[str] = Field(min_length=1)
    methods: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    inject: list[InjectWrite] = Field(default_factory=list)
    allow_insecure_http: bool = False
    allow_exec: bool = False


class ProjectRegistration(BaseModel):
    name: str | None = Field(default=None, max_length=80)


def _iso(value: datetime) -> str:
    return value.isoformat()


def create_dashboard_app(
    runtime: RuntimeContainer,
    context: DashboardContext,
    auth: DashboardAuth | None = None,
) -> FastAPI:
    auth = auth or DashboardAuth()
    app = FastAPI(title="Interpose Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = auth

    def scope_name(choice: str) -> str:
        if choice == "global":
            return GLOBAL_SCOPE
        project_id = runtime.scope_context.project_id
        if project_id is None:
            raise HTTPException(status_code=409, detail="this folder is not a registered project")
        return project_scope(project_id)

    def audit_admin(action: str, reference: str, scope: str, **details: Any) -> None:
        runtime.audit_logger.record(
            session="dashboard",
            agent="operator",
            secret_reference=reference,
            destination=scope,
            action=action,
            policy_result="not-applicable",
            status="success",
            duration_ms=0,
            details=details,
        )

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if not is_loopback_authority(host):
            return JSONResponse({"detail": "Host must be the loopback dashboard"}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None and origin != f"http://{host}":
            return JSONResponse({"detail": "cross-origin requests are not accepted"}, status_code=403)
        if request.headers.get("sec-fetch-site", "").lower() in {"cross-site", "same-site"}:
            return JSONResponse({"detail": "cross-site requests are not accepted"}, status_code=403)

        path = request.url.path
        session_id = request.cookies.get(SESSION_COOKIE)
        csrf = auth.csrf_for(session_id)
        public = path in {"/login", "/app.css"}
        if not public and csrf is None:
            if path.startswith("/api/") or path == "/app.js":
                response: Response = JSONResponse({"detail": "login required"}, status_code=401)
            else:
                response = HTMLResponse(
                    _LOGIN_REQUIRED_PAGE.format(message="This dashboard needs a login link."),
                    status_code=401,
                )
        elif request.method not in {"GET", "HEAD"} and not public and not hmac.compare_digest(
            request.headers.get(CSRF_HEADER, "").encode(), (csrf or "").encode()
        ):
            response = JSONResponse({"detail": "missing or invalid CSRF token"}, status_code=403)
        else:
            response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    @app.get("/login")
    def login(t: str = "") -> Response:
        session_id = auth.redeem(t)
        if session_id is None:
            return HTMLResponse(
                _LOGIN_REQUIRED_PAGE.format(message="This login link is invalid or was already used."),
                status_code=401,
            )
        # Redirect so the token leaves the address bar immediately.
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(resources.files(__package__).joinpath("static/index.html").read_text("utf-8"))

    for asset_path, media_type in _STATIC_FILES.items():
        def serve(asset_path: str = asset_path, media_type: str = media_type) -> Response:
            content = resources.files(__package__).joinpath(f"static{asset_path}").read_text("utf-8")
            return Response(content, media_type=media_type)

        app.add_api_route(asset_path, serve, methods=["GET"])

    @app.get("/api/session")
    def session(request: Request) -> dict[str, str]:
        return {"csrf": auth.csrf_for(request.cookies.get(SESSION_COOKIE)) or ""}

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        project = runtime.project
        chain = runtime.scope_context.chain()
        active_project_scope = runtime.scope_context.project_scope
        visible_scopes = set(chain)

        secrets_meta = [m for m in runtime.secret_store.list_metadata() if m.scope in visible_scopes]
        policies = [p for p in runtime.policy_repository.list() if p.scope in visible_scopes]
        by_reference: dict[str, dict[str, Any]] = {}

        secret_rows = []
        for meta in secrets_meta:
            secret_rows.append(
                {
                    "id": meta.id,
                    "scope": "project" if meta.scope == active_project_scope else "global",
                    "reference": meta.reference,
                    "fingerprint": meta.fingerprint.removeprefix("hmac-sha256:")[:12],
                    "updated_at": _iso(meta.updated_at),
                }
            )
            by_reference.setdefault(meta.reference, {})["secret_" + secret_rows[-1]["scope"]] = True

        policy_rows = []
        for record in policies:
            document = PolicyDocument.model_validate_json(record.definition)
            scope = "project" if record.scope == active_project_scope else "global"
            policy_rows.append(
                {
                    "id": record.id,
                    "scope": scope,
                    "secret": record.secret_reference,
                    "hosts": document.allow.hosts if document.allow else [],
                    "deny_hosts": document.deny.hosts if document.deny else [],
                    "methods": document.normalized_methods(),
                    "schemes": list(document.normalized_schemes()),
                    "paths": document.paths or [],
                    "inject": [
                        {"kind": slot.kind, "name": slot.name} for slot in document.injection_slots()
                    ],
                    "inject_is_default": document.inject is None,
                    "allow_exec": document.allow_exec,
                    "updated_at": _iso(record.updated_at),
                }
            )
            by_reference.setdefault(record.secret_reference, {})["policy_" + scope] = True

        effective = []
        for reference in sorted(by_reference):
            entry = by_reference[reference]
            secret_from = "project" if entry.get("secret_project") else "global" if entry.get("secret_global") else None
            policy_from = "project" if entry.get("policy_project") else "global" if entry.get("policy_global") else None
            effective.append(
                {
                    "reference": reference,
                    "secret_from": secret_from,
                    "policy_from": policy_from,
                    "ready": bool(secret_from and policy_from),
                }
            )

        return {
            "project": (
                {"id": project.id, "name": project.name, "root": project.root} if project else None
            ),
            "working_directory": str(context.working_directory),
            "proxy_url": context.proxy_url,
            "secrets": secret_rows,
            "policies": policy_rows,
            "effective": effective,
        }

    @app.post("/api/project")
    def register_project(payload: ProjectRegistration) -> dict[str, Any]:
        project = runtime.project_registry.register(context.working_directory, payload.name)
        runtime.scope_context.project_id = project.id
        audit_admin("ADMIN_PROJECT_REGISTER", "none", project_scope(project.id), root=project.root)
        return {"id": project.id, "name": project.name, "root": project.root}

    @app.post("/api/secrets", status_code=201)
    def write_secret(payload: SecretWrite) -> dict[str, Any]:
        scope = scope_name(payload.scope)
        try:
            reference = normalize_secret_reference(payload.reference)
        except SecretReferenceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            meta = runtime.secret_store.store(reference, payload.value, scope=scope)
        except SecretValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit_admin("ADMIN_SECRET_SET", meta.reference, scope)
        # Deliberately no value, and no full fingerprint, in the response.
        return {
            "reference": meta.reference,
            "scope": payload.scope,
            "trimmed": payload.value != payload.value.strip(),
        }

    @app.delete("/api/secrets")
    def delete_secret(scope: Literal["global", "project"], reference: str) -> dict[str, bool]:
        resolved_scope = scope_name(scope)
        try:
            canonical = SecretReference.parse(reference).canonical
        except SecretReferenceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deleted = runtime.secret_store.delete(canonical, scope=resolved_scope)
        if not deleted:
            raise HTTPException(status_code=404, detail="secret not found")
        audit_admin("ADMIN_SECRET_DELETE", canonical, resolved_scope)
        return {"deleted": True}

    @app.post("/api/policies", status_code=201)
    def write_policy(payload: PolicyWrite) -> dict[str, Any]:
        scope = scope_name(payload.scope)
        definition: dict[str, Any] = {
            "secret": payload.secret,
            "allow": {"hosts": [host.strip().lower() for host in payload.hosts if host.strip()]},
        }
        if payload.methods:
            definition["methods"] = [method.strip().upper() for method in payload.methods if method.strip()]
        if payload.paths:
            definition["paths"] = [path.strip() for path in payload.paths if path.strip()]
        if payload.inject:
            definition["inject"] = [{slot.kind: slot.name.strip()} for slot in payload.inject]
        if payload.allow_insecure_http:
            definition["schemes"] = ["https", "http"]
        if payload.allow_exec:
            definition["allow_exec"] = True
        try:
            document = PolicyDocument.model_validate(definition)
            normalize_secret_reference(document.secret)
        except (ValidationError, PolicyError, SecretReferenceError, ScopeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        record = runtime.policy_repository.store(document, scope=scope)
        audit_admin("ADMIN_POLICY_SET", record.secret_reference, scope, hosts=definition["allow"]["hosts"])
        return {"id": record.id}

    @app.delete("/api/policies/{policy_id}")
    def delete_policy(policy_id: int) -> dict[str, bool]:
        record = runtime.policy_repository.get(policy_id)
        if record is None or record.scope not in runtime.scope_context.chain():
            raise HTTPException(status_code=404, detail="policy not found")
        runtime.policy_repository.delete(policy_id)
        audit_admin("ADMIN_POLICY_DELETE", record.secret_reference, record.scope)
        return {"deleted": True}

    @app.get("/api/audit")
    def audit(limit: int = 200) -> list[dict[str, Any]]:
        entries = runtime.audit_logger.list(limit=max(1, min(limit, 1000)))  # newest first
        return [
            {
                "id": entry.id,
                "timestamp": _iso(entry.timestamp),
                "agent": entry.agent,
                "session": entry.session,
                "reference": entry.secret_reference,
                "destination": entry.destination,
                "action": entry.action,
                "result": entry.policy_result,
                "status": entry.status,
                "reason": entry.details.get("reason"),
                "location": entry.details.get("location"),
            }
            for entry in entries
        ]

    return app
