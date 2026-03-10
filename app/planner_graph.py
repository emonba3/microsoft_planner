from __future__ import annotations

import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv

load_dotenv()

GRAPH_BASE_URL = os.environ.get("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0").rstrip("/")
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID") or os.environ.get("OIDC_CLIENT_ID")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET") or os.environ.get("OIDC_CLIENT_SECRET")
MS_TENANT_ID = os.environ.get("MS_TENANT_ID", "common")
MS_REDIRECT_URI = os.environ.get("MS_REDIRECT_URI") or os.environ.get("OIDC_REDIRECT_URI")
MS_SCOPES = os.environ.get(
    "MS_SCOPES",
    "openid profile email offline_access User.Read Tasks.Read GroupMember.Read.All User.ReadBasic.All",
)


def _tenant_base() -> str:
    return f"https://login.microsoftonline.com/{MS_TENANT_ID}"


def _token_url() -> str:
    return f"{_tenant_base()}/oauth2/v2.0/token"


def _authorize_url() -> str:
    return f"{_tenant_base()}/oauth2/v2.0/authorize"


def build_microsoft_auth_url(state: str, *, code_challenge: Optional[str] = None) -> str:
    if not (MS_CLIENT_ID and MS_REDIRECT_URI):
        raise RuntimeError("MS_CLIENT_ID / MS_REDIRECT_URI are not set")

    params = {
        "client_id": MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": MS_REDIRECT_URI,
        "response_mode": "query",
        "scope": MS_SCOPES,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return f"{_authorize_url()}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str, *, code_verifier: Optional[str] = None) -> Dict[str, Any]:
    if not (MS_CLIENT_ID and MS_REDIRECT_URI):
        raise RuntimeError("MS_CLIENT_ID / MS_REDIRECT_URI are not set")

    data = {
        "client_id": MS_CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": MS_REDIRECT_URI,
        "scope": MS_SCOPES,
    }
    if MS_CLIENT_SECRET:
        data["client_secret"] = MS_CLIENT_SECRET
    if code_verifier:
        data["code_verifier"] = code_verifier

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(_token_url(), data=data, headers={"Accept": "application/json"})
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise httpx.HTTPStatusError(
                f"Microsoft token exchange failed: {resp.status_code} {detail}",
                request=resp.request,
                response=resp,
            )
        return resp.json()


async def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    data = {
        "client_id": MS_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": MS_REDIRECT_URI,
        "scope": MS_SCOPES,
    }
    if MS_CLIENT_SECRET:
        data["client_secret"] = MS_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(_token_url(), data=data, headers={"Accept": "application/json"})
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise httpx.HTTPStatusError(
                f"Microsoft token refresh failed: {resp.status_code} {detail}",
                request=resp.request,
                response=resp,
            )
        return resp.json()


async def graph_request(
    method: str,
    path: str,
    *,
    access_token: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if not path.startswith("/"):
        path = "/" + path
    url = f"{GRAPH_BASE_URL}{path}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    if method.upper() in {"POST", "PATCH", "PUT"}:
        headers["Content-Type"] = "application/json"

    async with httpx.AsyncClient(timeout=45) as client:
        resp = await client.request(method.upper(), url, params=params, json=json_body, headers=headers)

    if resp.status_code >= 400:
        try:
            err = resp.json()
        except Exception:
            err = resp.text
        raise httpx.HTTPStatusError(
            f"Microsoft Graph error {resp.status_code} for {method.upper()} {url}: {err}",
            request=resp.request,
            response=resp,
        )

    if resp.status_code == 204:
        return {"ok": True, "status_code": 204}

    if "application/json" in (resp.headers.get("content-type") or "").lower():
        return resp.json()
    return {"ok": True, "status_code": resp.status_code, "text": resp.text}


async def graph_get_paged(
    path: str,
    *,
    access_token: str,
    params: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    max_pages: int = 20,
) -> Dict[str, Any]:
    combined = []
    next_url: Optional[str] = None
    current_path = path
    current_params = dict(params or {})
    pages = 0
    last_payload: Dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=45) as client:
        while pages < max_pages:
            pages += 1
            if next_url:
                url = next_url
                req_params = None
            else:
                if not current_path.startswith("/"):
                    current_path = "/" + current_path
                url = f"{GRAPH_BASE_URL}{current_path}"
                req_params = current_params

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }
            if extra_headers:
                headers.update(extra_headers)

            resp = await client.get(url, params=req_params, headers=headers)
            if resp.status_code >= 400:
                try:
                    err = resp.json()
                except Exception:
                    err = resp.text
                raise httpx.HTTPStatusError(
                    f"Microsoft Graph error {resp.status_code} for GET {url}: {err}",
                    request=resp.request,
                    response=resp,
                )
            payload = resp.json()
            last_payload = payload
            combined.extend(payload.get("value", []))
            next_url = payload.get("@odata.nextLink")
            if not next_url:
                break

    result = dict(last_payload)
    result["value"] = combined
    result["pages_fetched"] = pages
    return result
