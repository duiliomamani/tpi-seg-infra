from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException, Request, Response

from backend import settings

logger = logging.getLogger("support.auth")


@dataclass
class LoginAttempt:
    nonce: str
    verifier: str
    expires_at: float


@dataclass
class UserSession:
    access_token: str
    refresh_token: str
    access_expires_at: float
    subject: str
    display_name: str
    email: str
    roles: list[str]
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    consented_tools: set[str] = field(default_factory=set)
    expires_at: float = field(default_factory=lambda: time.time() + settings.SESSION_TTL_SECONDS)
    pending_actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    recent_requests: list[float] = field(default_factory=list)
    audit_events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=300), repr=False)
    audit_subscribers: set[asyncio.Queue[dict[str, Any]]] = field(default_factory=set, repr=False)
    audit_sequence: int = 0


LOGIN_ATTEMPTS: dict[str, LoginAttempt] = {}
SESSIONS: dict[str, UserSession] = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def verify_mcp_access_token(token: str) -> dict[str, Any]:
    jwks = jwt.PyJWKClient(f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/certs")
    signing_key = jwks.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="mcp-support",
        issuer=settings.OIDC_ISSUER,
        options={"require": ["iss", "sub", "aud", "exp", "iat"]},
    )
    audience = claims.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]
    if settings.OIDC_CLIENT_ID != claims.get("azp") or "mcp-support" not in audience:
        raise jwt.InvalidTokenError("Unexpected access-token audience or authorized party")
    token_scopes = set(str(claims.get("scope", "")).split())
    if not {"support:read", "support:write"}.issubset(token_scopes):
        raise jwt.InvalidTokenError("Access token is missing required support scopes")
    return claims


def clean_expired() -> None:
    now = time.time()
    for state in [key for key, item in LOGIN_ATTEMPTS.items() if item.expires_at < now]:
        LOGIN_ATTEMPTS.pop(state, None)
    for session_id in [key for key, item in SESSIONS.items() if item.expires_at < now]:
        SESSIONS.pop(session_id, None)


def create_login_redirect(response: Response) -> str:
    clean_expired()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = b64url(secrets.token_bytes(48))
    LOGIN_ATTEMPTS[state] = LoginAttempt(nonce=nonce, verifier=verifier, expires_at=time.time() + 300)
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    response.set_cookie(
        settings.OIDC_STATE_COOKIE,
        state,
        max_age=300,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/auth/callback",
    )
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid support:read support:write",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{settings.OIDC_ISSUER}/protocol/openid-connect/auth?{urlencode(params)}"


async def finish_login(code: str, state: str, state_cookie: str | None) -> UserSession:
    attempt = LOGIN_ATTEMPTS.pop(state, None)
    if not attempt or not state_cookie or not hmac.compare_digest(state, state_cookie):
        raise HTTPException(status_code=400, detail="La sesión de inicio de sesión venció. Volvé a intentarlo.")
    if attempt.expires_at < time.time():
        raise HTTPException(status_code=400, detail="La sesión de inicio de sesión venció. Volvé a intentarlo.")

    token_url = f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/token"
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_response = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": settings.OIDC_CLIENT_ID,
                "client_secret": settings.OIDC_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.OIDC_REDIRECT_URI,
                "code_verifier": attempt.verifier,
            },
        )
    if token_response.is_error:
        raise HTTPException(status_code=401, detail="Keycloak rechazó el inicio de sesión.")
    tokens = token_response.json()
    id_token = tokens.get("id_token")
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not id_token or not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Keycloak no devolvió las credenciales esperadas.")

    try:
        jwks = jwt.PyJWKClient(f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/certs")
        signing_key = jwks.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.OIDC_CLIENT_ID,
            issuer=settings.OIDC_ISSUER,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        )
    except Exception as exc:
        # Authentication errors are deliberately kept generic in the browser response.
        raise HTTPException(status_code=401, detail="No se pudo validar la identidad recibida.") from exc
    if not hmac.compare_digest(str(claims.get("nonce", "")), attempt.nonce):
        raise HTTPException(status_code=401, detail="No se pudo validar la sesión de identidad.")
    id_audience = claims.get("aud", [])
    if isinstance(id_audience, str):
        id_audience = [id_audience]
    authorized_party = claims.get("azp")
    if (authorized_party and authorized_party != settings.OIDC_CLIENT_ID) or (
        len(id_audience) > 1 and authorized_party != settings.OIDC_CLIENT_ID
    ):
        raise HTTPException(status_code=401, detail="La respuesta de identidad no está dirigida a esta aplicación.")

    try:
        access_claims = verify_mcp_access_token(access_token)
    except jwt.PyJWTError as exc:
        logger.warning("OIDC access-token validation failed: %s", str(exc)[:160])
        raise HTTPException(status_code=401, detail="El proveedor devolvió un token inválido.") from exc
    if not hmac.compare_digest(str(access_claims["sub"]), str(claims["sub"])):
        raise HTTPException(status_code=401, detail="La identidad de los tokens no coincide.")

    realm_roles = access_claims.get("realm_access", {}).get("roles", [])
    roles = [role for role in realm_roles if role in {"employee", "support_l1", "support_admin"}]
    session = UserSession(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=time.time() + int(tokens.get("expires_in", 60)),
        subject=str(claims["sub"]),
        display_name=str(claims.get("name") or claims.get("preferred_username") or "Usuario"),
        email=str(claims.get("email") or ""),
        roles=roles,
    )
    return session


def establish_session(response: Response, session: UserSession) -> None:
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = session
    response.set_cookie(
        settings.SESSION_COOKIE,
        session_id,
        max_age=settings.SESSION_TTL_SECONDS,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def current_session(request: Request) -> tuple[str, UserSession]:
    clean_expired()
    session_id = request.cookies.get(settings.SESSION_COOKIE)
    session = SESSIONS.get(session_id or "")
    if not session:
        raise HTTPException(status_code=401, detail="Iniciá sesión para continuar.")
    session.expires_at = time.time() + settings.SESSION_TTL_SECONDS
    return str(session_id), session


def require_csrf(request: Request, session: UserSession) -> None:
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != settings.APP_ORIGIN.rstrip("/"):
        raise HTTPException(status_code=403, detail="Origen no permitido.")
    csrf = request.headers.get("x-csrf-token", "")
    if not csrf or not hmac.compare_digest(csrf, session.csrf_token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido.")


async def get_mcp_access_token(session: UserSession) -> str:
    if session.access_expires_at > time.time() + 20:
        return session.access_token
    token_url = f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/token"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.OIDC_CLIENT_ID,
                "client_secret": settings.OIDC_CLIENT_SECRET,
                "refresh_token": session.refresh_token,
            },
        )
    if response.is_error:
        SESSIONS.pop(next((key for key, value in SESSIONS.items() if value is session), ""), None)
        raise HTTPException(status_code=401, detail="La sesión venció. Iniciá sesión nuevamente.")
    tokens = response.json()
    refreshed_access_token = str(tokens.get("access_token") or "")
    try:
        access_claims = verify_mcp_access_token(refreshed_access_token)
    except jwt.PyJWTError as exc:
        SESSIONS.pop(next((key for key, value in SESSIONS.items() if value is session), ""), None)
        raise HTTPException(status_code=401, detail="El proveedor devolvió un token inválido.") from exc
    if not hmac.compare_digest(str(access_claims["sub"]), session.subject):
        SESSIONS.pop(next((key for key, value in SESSIONS.items() if value is session), ""), None)
        raise HTTPException(status_code=401, detail="La identidad de los tokens no coincide.")
    session.access_token = refreshed_access_token
    session.refresh_token = str(tokens.get("refresh_token") or session.refresh_token)
    session.access_expires_at = time.time() + int(tokens.get("expires_in", 60))
    return session.access_token


def make_approval_proof(session_id: str, subject: str, action_id: str, summary: str, description: str, expires_at: int) -> str:
    import json

    payload = {
        "session": session_id,
        "sub": subject,
        "action": "ticket:create",
        "action_id": action_id,
        "summary": summary,
        "description": description,
        "exp": expires_at,
    }
    encoded = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = hmac.new(settings.ACTION_SIGNING_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{b64url(signature)}"


def make_mfa_reset_approval_proof(session_id: str, subject: str, action_id: str, username: str, expires_at: int) -> str:
    import json

    payload = {
        "session": session_id,
        "sub": subject,
        "action": "mfa:reset",
        "action_id": action_id,
        "username": username,
        "exp": expires_at,
    }
    encoded = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = hmac.new(settings.ACTION_SIGNING_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{b64url(signature)}"


def make_product_price_approval_proof(
    session_id: str,
    subject: str,
    action_id: str,
    sku: str,
    new_price_ars: int,
    expires_at: int,
) -> str:
    import json

    payload = {
        "session": session_id,
        "sub": subject,
        "action": "product_price:update",
        "action_id": action_id,
        "sku": sku,
        "new_price_ars": new_price_ars,
        "exp": expires_at,
    }
    encoded = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = hmac.new(settings.ACTION_SIGNING_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{b64url(signature)}"
