from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app import db
from app.crypto import encrypt
from app.db import init_db
from app.mcp_app import mcp
from app.oauth_verify import verify_bearer_token
from app.planner_graph import build_microsoft_auth_url, exchange_code_for_tokens, graph_request
from app.request_context import current_user
from app.ui import router as ui_router

load_dotenv()

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("planner_mcp")


def _pkce_challenge(verifier: str) -> str:
    import hashlib, base64
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

@asynccontextmanager
async def lifespan(app_: FastAPI):
    async with mcp.session_manager.run():
        await init_db()
        yield


app = FastAPI(redirect_slashes=False, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "change-me"),
    same_site="lax",
    https_only=True,
)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")
if os.environ.get("ENABLE_TRUSTED_HOST", "0").lower() in {"1", "true", "yes"}:
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    allowed = os.environ.get("ALLOWED_HOSTS", "").strip()
    allowed_hosts = [h.strip() for h in allowed.split(",") if h.strip()] or ["localhost", "127.0.0.1"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

app.include_router(ui_router)


@app.get("/")
def root():
    return {"ok": True, "service": "Microsoft 365 Planner MCP Server", "ui": "/ui", "mcp": "/mcp"}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/microsoft/connect")
async def microsoft_connect(request: Request, state: str):
    if state != request.session.get("ms_state"):
        return JSONResponse({"error": "Invalid state"}, status_code=400)
    verifier = request.session.get("ms_code_verifier")
    return RedirectResponse(build_microsoft_auth_url(state=state, code_challenge=_pkce_challenge(verifier) if verifier else None))


@app.get("/microsoft/callback")
async def microsoft_callback(request: Request, code: str, state: Optional[str] = None):
    if state != request.session.get("ms_state"):
        return JSONResponse({"error": "Invalid state"}, status_code=400)
    tokens = await exchange_code_for_tokens(code, code_verifier=request.session.get("ms_code_verifier"))
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        return JSONResponse({"error": "No refresh token returned. Ensure offline_access is granted."}, status_code=400)

    me = await graph_request("GET", "/me", access_token=access_token)
    org = await graph_request("GET", "/organization", access_token=access_token)
    org_item = (org.get("value") or [{}])[0]
    tenant_id = org_item.get("id") or me.get("id")
    tenant_name = org_item.get("displayName") or org_item.get("tenantType") or "Microsoft 365"
    expires_in = int(tokens.get("expires_in", 3600))
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    user = request.session.get("user") or {}
    user_id = (user.get("sub") or user.get("email") or me.get("id") or "unknown_user").strip()

    await db.upsert_connection(
        user_id=user_id,
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        access_token_enc=encrypt(access_token),
        refresh_token_enc=encrypt(refresh_token),
        access_token_expires_at=expires_at,
    )
    return RedirectResponse(url="/ui", status_code=302)


def _normalized_issuer_from_env() -> Optional[str]:
    issuer = os.environ.get("OIDC_ISSUER")
    if issuer:
        return issuer.rstrip("/") + "/"
    dom = os.environ.get("OAUTH_ISSUER_DOMAIN")
    if dom:
        return f"https://{dom.rstrip('/')}/"
    return None


def _authorization_endpoint() -> Optional[str]:
    ep = os.environ.get("OIDC_AUTHORIZATION_ENDPOINT")
    if ep:
        return ep
    issuer = _normalized_issuer_from_env()
    if issuer:
        return f"{issuer.rstrip('/')}/authorize"
    return None


def _token_endpoint() -> Optional[str]:
    ep = os.environ.get("OIDC_TOKEN_ENDPOINT")
    if ep:
        return ep
    issuer = _normalized_issuer_from_env()
    if issuer:
        return f"{issuer.rstrip('/')}/oauth/token"
    return None


def _jwks_uri() -> Optional[str]:
    uri = os.environ.get("OIDC_JWKS_URI")
    if uri:
        return uri
    dom = os.environ.get("OAUTH_ISSUER_DOMAIN")
    if dom:
        return f"https://{dom.rstrip('/')}/.well-known/jwks.json"
    return None


def _registration_endpoint() -> Optional[str]:
    ep = os.environ.get("OIDC_REGISTRATION_ENDPOINT")
    if ep:
        return ep
    return None


def _supported_scopes() -> list[str]:
    raw = os.environ.get("OAUTH_SCOPES", "openid profile email offline_access")
    return [s for s in raw.replace(",", " ").split() if s]


def _public_base_url_from_request(request: Request) -> str:
    env_url = os.environ.get("PUBLIC_BASE_URL") or os.environ.get("BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if env_url:
        return env_url.rstrip("/")
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    if host:
        return f"{proto}://{host}".rstrip("/")
    return ""


def _resource_url(request: Request) -> str:
    resource = os.environ.get("OAUTH_RESOURCE")
    if resource:
        return resource.rstrip("/")
    base = _public_base_url_from_request(request).rstrip("/")
    return f"{base}/mcp" if base else "/mcp"


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
def oauth_protected_resource(request: Request):
    issuer = _normalized_issuer_from_env()
    return {
        "resource": _resource_url(request),
        "authorization_servers": [issuer] if issuer else [],
        "scopes_supported": _supported_scopes(),
        "bearer_methods_supported": ["header"],
        "resource_documentation": os.environ.get("RESOURCE_DOCUMENTATION"),
    }


@app.get("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    return {
        "issuer": _normalized_issuer_from_env(),
        "authorization_endpoint": _authorization_endpoint(),
        "token_endpoint": _token_endpoint(),
        "registration_endpoint": _registration_endpoint(),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": _supported_scopes(),
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
    }


@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return {
        "issuer": _normalized_issuer_from_env(),
        "authorization_endpoint": _authorization_endpoint(),
        "token_endpoint": _token_endpoint(),
        "registration_endpoint": _registration_endpoint(),
        "jwks_uri": _jwks_uri(),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    }


class MCPHttpOAuthWrapper:
    def __init__(self, asgi_app: Any):
        self._app = asgi_app

    @staticmethod
    def _extract_jsonrpc_methods(body: bytes) -> list[str]:
        if not body:
            return []
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return []
        msgs = payload if isinstance(payload, list) else [payload]
        methods: list[str] = []
        for msg in msgs:
            if isinstance(msg, dict) and msg.get("method"):
                methods.append(str(msg.get("method")))
        return methods

    class _BodyBuffer:
        def __init__(self, receive):
            self._receive = receive
            self._body: Optional[bytes] = None
            self._queue: Optional[list] = None

        async def body(self) -> bytes:
            if self._body is not None:
                return self._body
            chunks: list[bytes] = []
            more = True
            while more:
                message = await self._receive()
                if message.get("type") != "http.request":
                    continue
                chunks.append(message.get("body", b""))
                more = bool(message.get("more_body", False))
            self._body = b"".join(chunks)
            self._queue = [{"type": "http.request", "body": self._body, "more_body": False}]
            return self._body

        async def replay(self):
            if self._queue is None:
                return await self._receive()
            if self._queue:
                return self._queue.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

    def _challenge_headers(self, scope: Dict[str, Any]) -> Dict[str, str]:
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in (scope.get("headers") or [])}
        proto = headers.get("x-forwarded-proto") or scope.get("scheme") or "https"
        host = headers.get("x-forwarded-host") or headers.get("host")
        base = os.environ.get("PUBLIC_BASE_URL") or os.environ.get("BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL")
        if base:
            base = base.rstrip("/")
        elif host:
            base = f"{proto}://{host}".rstrip("/")
        else:
            base = ""
        resource_metadata_url = f"{base}/.well-known/oauth-protected-resource" if base else "/.well-known/oauth-protected-resource"
        scope_str = " ".join(_supported_scopes())
        www_auth = f'Bearer resource_metadata="{resource_metadata_url}"'
        if scope_str:
            www_auth += f', scope="{scope_str}"'
        return {"WWW-Authenticate": www_auth}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        body_buf = self._BodyBuffer(receive)
        path = (scope.get("path") or "").rstrip("/")
        if not (path == "/mcp" or path.startswith("/mcp/") or path == "/sse" or path.startswith("/sse/")):
            await self._app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in (scope.get("headers") or [])}
        auth = headers.get("authorization")
        allow_public_discovery = os.environ.get("ALLOW_PUBLIC_DISCOVERY", "1").lower() in {"1", "true", "yes"}
        if allow_public_discovery and (not auth or not auth.lower().startswith("bearer ")) and path.startswith("/mcp"):
            try:
                body = await body_buf.body()
                if not body and scope.get("method") == "POST":
                    resp = JSONResponse({"ok": True, "message": "MCP endpoint ready. Send JSON-RPC methods via POST."})
                    await resp(scope, receive, send)
                    return
                methods = self._extract_jsonrpc_methods(body)
                public_methods = {"initialize", "tools/list", "resources/list", "prompts/list", "logging/setLevel", "ping"}
                if methods and all(m in public_methods or m.startswith("notifications/") for m in methods):
                    await self._app(scope, body_buf.replay, send)
                    return
            except Exception:
                pass

        expected_resource = None
        try:
            proto = headers.get("x-forwarded-proto") or scope.get("scheme") or "https"
            host = headers.get("x-forwarded-host") or headers.get("host")
            base = os.environ.get("PUBLIC_BASE_URL") or os.environ.get("BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL")
            if base:
                base = base.rstrip("/")
            elif host:
                base = f"{proto}://{host}".rstrip("/")
            else:
                base = ""
            expected_resource = os.environ.get("OAUTH_RESOURCE") or (f"{base}/mcp" if base else None)
        except Exception:
            expected_resource = os.environ.get("OAUTH_RESOURCE")

        try:
            claims = await verify_bearer_token(auth, audience=expected_resource)
        except PermissionError as e:
            logger.info("MCP auth rejected: path=%s expected_audience=%s reason=%s", path, expected_resource, str(e))
            challenge = self._challenge_headers(scope)
            if path == "/sse" or path.startswith("/sse/"):
                resp = Response("event: error\ndata: unauthorized\n\n", status_code=401, media_type="text/event-stream", headers=challenge)
                await resp(scope, receive, send)
                return
            resp = JSONResponse({"error": "unauthorized", "error_description": str(e)}, status_code=401, headers=challenge)
            await resp(scope, receive, send)
            return
        except Exception as e:
            logger.exception("Unexpected OAuth verification error")
            resp = JSONResponse({"error": f"OAuth verify error: {e}"}, status_code=500)
            await resp(scope, receive, send)
            return

        token = current_user.set({"sub": claims.get("sub"), "email": claims.get("email")})
        try:
            await self._app(scope, body_buf.replay, send)
        finally:
            current_user.reset(token)


app.mount("/", MCPHttpOAuthWrapper(mcp.streamable_http_app()))
