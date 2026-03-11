from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv

load_dotenv()

OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/") + "/"
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid profile email offline_access")

_discovery_cache = None


async def oidc_discovery() -> dict:
    global _discovery_cache
    if _discovery_cache:
        return _discovery_cache
    if not OIDC_ISSUER or OIDC_ISSUER == "/":
        raise RuntimeError("OIDC_ISSUER is not set")

    url = f"{OIDC_ISSUER}.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(url)
        r.raise_for_status()
        _discovery_cache = r.json()
        return _discovery_cache


async def build_login_url(state: str, *, code_challenge: Optional[str] = None) -> str:
    if not (OIDC_CLIENT_ID and OIDC_REDIRECT_URI):
        raise RuntimeError("OIDC_CLIENT_ID / OIDC_REDIRECT_URI not set")

    d = await oidc_discovery()
    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": OIDC_SCOPES,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    return f"{d['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str, *, code_verifier: Optional[str] = None) -> dict:
    if not (OIDC_CLIENT_ID and OIDC_REDIRECT_URI):
        raise RuntimeError("OIDC_CLIENT_ID / OIDC_REDIRECT_URI not set")

    d = await oidc_discovery()
    data = {
        "grant_type": "authorization_code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "code": code,
        "scope": OIDC_SCOPES,
    }

    if OIDC_CLIENT_SECRET:
        data["client_secret"] = OIDC_CLIENT_SECRET
    if code_verifier:
        data["code_verifier"] = code_verifier

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            d["token_endpoint"],
            data=data,
            headers={"Accept": "application/json"},
        )
    r.raise_for_status()
    return r.json()


async def fetch_userinfo(access_token: str) -> dict:
    d = await oidc_discovery()
    userinfo_endpoint = d.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise RuntimeError("userinfo_endpoint not found in OIDC discovery")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()