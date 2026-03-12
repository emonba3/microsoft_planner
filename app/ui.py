from __future__ import annotations

import os
import secrets
import hashlib
import base64

from fastapi import APIRouter, Request, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from app import db
from app.oidc_client import build_login_url, exchange_code_for_tokens, fetch_userinfo

templates = Jinja2Templates(directory="templates")
router = APIRouter(prefix="/ui")


def _uid(request: Request) -> str | None:
    u = request.session.get("user")
    if not u:
        return None
    val = u.get("email") or u.get("sub")
    return val.strip().lower() if isinstance(val, str) else val


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request):
    user_id = _uid(request)
    if not user_id:
        return RedirectResponse("/ui/login")

    connections = await db.list_connections(user_id)
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    mcp_url = f"{base}/mcp" if base else "/mcp"
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": request.session.get("user"), "connections": connections, "mcp_url": mcp_url},
    )


@router.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    verifier = secrets.token_urlsafe(64)
    request.session["oidc_code_verifier"] = verifier
    challenge = _pkce_challenge(verifier)
    return RedirectResponse(await build_login_url(state, code_challenge=challenge))


@router.get("/callback")
async def callback(request: Request, code: str, state: str):
    if state != request.session.get("oidc_state"):
        return HTMLResponse("Invalid state", status_code=400)

    verifier = request.session.get("oidc_code_verifier")
    try:
        tokens = await exchange_code_for_tokens(code, code_verifier=verifier)
    except Exception as e:
        return HTMLResponse(f"OIDC token exchange failed: {e}", status_code=500)

    access_token = tokens.get("access_token")
    userinfo = {}
    if access_token:
        try:
            userinfo = await fetch_userinfo(access_token)
        except Exception:
            userinfo = {}

    user = {
        "email": userinfo.get("email") or userinfo.get("preferred_username"),
        "sub": userinfo.get("sub") or userinfo.get("oid") or userinfo.get("id"),
        "name": userinfo.get("name") or userinfo.get("preferred_username"),
    }
    request.session["user"] = user
    return RedirectResponse("/ui")


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/ui")


@router.get("/connect-planner")
async def connect_planner(request: Request):
    user_id = _uid(request)
    if not user_id:
        return RedirectResponse("/ui/login")
    state = secrets.token_urlsafe(24)
    request.session["ms_state"] = state
    verifier = secrets.token_urlsafe(64)
    request.session["ms_code_verifier"] = verifier
    return RedirectResponse(f"/microsoft/connect?state={state}")


@router.get("/mcp", response_class=HTMLResponse)
async def mcp_page(request: Request):
    user_id = _uid(request)
    if not user_id:
        return RedirectResponse("/ui/login")
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    mcp_url = f"{base}/mcp" if base else "/mcp"
    return templates.TemplateResponse(
        "mcp.html",
        {"request": request, "user": request.session.get("user"), "mcp_url": mcp_url},
    )


@router.post("/disconnect-planner")
async def disconnect_planner(request: Request, tenant_id: str = Query(...)):
    user_id = _uid(request)
    if not user_id:
        return RedirectResponse("/ui/login", status_code=302)
    await db.delete_connection(user_id, tenant_id)
    return RedirectResponse("/ui", status_code=302)
