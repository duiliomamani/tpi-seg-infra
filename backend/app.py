from __future__ import annotations

import time
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import settings
from backend.agent import respond
from backend.auth import (
    SESSIONS,
    UserSession,
    create_login_redirect,
    current_session,
    establish_session,
    finish_login,
    get_mcp_access_token,
    make_approval_proof,
    require_csrf,
)
from backend.mcp_client import MCPToolFailure, call_support_tool
from backend.store import initialize


initialize()

app = FastAPI(
    title="Support Desk PoC",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if settings.COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if (FRONTEND_DIR / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


class ChatInput(BaseModel):
    message: str = Field(min_length=1, max_length=settings.MAX_CHAT_LENGTH)


class ToolConsentInput(BaseModel):
    tool: Literal["search_kb", "get_my_ticket"]
    allowed: bool


class ModelConsentInput(BaseModel):
    allowed: bool


class ConfirmActionInput(BaseModel):
    summary: str = Field(min_length=6, max_length=120)
    description: str = Field(min_length=12, max_length=700)


def enforce_rate_limit(session: UserSession) -> None:
    now = time.time()
    session.recent_requests = [stamp for stamp in session.recent_requests if now - stamp < 60]
    if len(session.recent_requests) >= 20:
        raise HTTPException(status_code=429, detail="Alcanzaste el límite de mensajes por minuto. Esperá un momento.")
    session.recent_requests.append(now)


@app.get("/auth/login")
async def login(response: Response) -> Response:
    redirect = RedirectResponse(create_login_redirect(response), status_code=302)
    # Copy the transient state cookie set by create_login_redirect onto the redirect response.
    for key, value in response.headers.items():
        if key.lower() == "set-cookie":
            redirect.headers.append(key, value)
    return redirect


@app.get("/auth/callback")
async def login_callback(request: Request, code: str | None = None, state: str | None = None) -> Response:
    if not code or not state:
        raise HTTPException(status_code=400, detail="La respuesta de inicio de sesión está incompleta.")
    session = await finish_login(code, state, request.cookies.get(settings.OIDC_STATE_COOKIE))
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(settings.OIDC_STATE_COOKIE, path="/auth/callback")
    establish_session(response, session)
    return response


@app.get("/api/me")
async def me(request: Request) -> dict[str, object]:
    _, session = current_session(request)
    return {
        "authenticated": True,
        "name": session.display_name,
        "email": session.email,
        "roles": session.roles,
        "consented_tools": sorted(session.consented_tools),
        "model_consent": session.model_consent,
        "model_configured": bool(settings.LLM_API_KEY),
        "model_name": settings.LLM_MODEL if settings.LLM_API_KEY else None,
        "model_local": settings.LLM_LOCAL,
        "csrf_token": session.csrf_token,
    }


@app.post("/api/consent/tool")
async def set_tool_consent(request: Request, body: ToolConsentInput) -> dict[str, object]:
    _, session = current_session(request)
    require_csrf(request, session)
    if body.allowed:
        session.consented_tools.add(body.tool)
    else:
        session.consented_tools.discard(body.tool)
    return {"consented_tools": sorted(session.consented_tools)}


@app.post("/api/consent/model")
async def set_model_consent(request: Request, body: ModelConsentInput) -> dict[str, bool]:
    _, session = current_session(request)
    require_csrf(request, session)
    session.model_consent = bool(body.allowed and settings.LLM_API_KEY)
    return {"model_consent": session.model_consent}


@app.post("/api/chat")
async def chat(request: Request, body: ChatInput) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    enforce_rate_limit(session)
    for action_id, pending in list(session.pending_actions.items()):
        if pending["expires_at"] < time.time():
            session.pending_actions.pop(action_id, None)
    token = await get_mcp_access_token(session)
    return await respond(body.message.strip(), session_id, session, token)


@app.post("/api/actions/{action_id}/confirm")
async def confirm_action(request: Request, action_id: str, body: ConfirmActionInput) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    pending = session.pending_actions.get(action_id)
    if not pending or pending["expires_at"] < time.time():
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="La acción venció. Volvé a preparar el ticket.")
    expires_at = min(int(pending["expires_at"]), int(time.time() + 180))
    proof = make_approval_proof(
        session_id,
        session.subject,
        action_id,
        body.summary.strip(),
        body.description.strip(),
        expires_at,
    )
    token = await get_mcp_access_token(session)
    try:
        result = await call_support_tool(
            token,
            "create_support_ticket",
            {
                "summary": body.summary.strip(),
                "description": body.description.strip(),
                "approval_proof": proof,
            },
        )
    except MCPToolFailure as exc:
        if exc.kind == "forbidden":
            raise HTTPException(status_code=403, detail="La política de acceso no autorizó crear el ticket.") from exc
        if exc.kind == "conflict":
            raise HTTPException(status_code=409, detail="La confirmación venció. Volvé a revisar la tarjeta del ticket.") from exc
        raise HTTPException(status_code=503, detail="No fue posible confirmar el ticket. Podés reintentar mientras la tarjeta siga vigente.") from exc
    session.pending_actions.pop(action_id, None)
    return {
        "kind": "message",
        "text": f"Listo, creé el ticket {result.get('ticket_id', 'nuevo')} con estado {result.get('status', 'Nuevo')}.",
        "sources": [],
    }


@app.post("/api/actions/{action_id}/cancel")
async def cancel_action(request: Request, action_id: str) -> dict[str, str]:
    _, session = current_session(request)
    require_csrf(request, session)
    session.pending_actions.pop(action_id, None)
    return {"status": "cancelled"}


@app.post("/auth/logout")
async def logout(request: Request, response: Response) -> Response:
    session_id, session = current_session(request)
    require_csrf(request, session)
    SESSIONS.pop(session_id, None)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/logout",
                data={
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "refresh_token": session.refresh_token,
                },
            )
    except httpx.HTTPError:
        pass
    result = Response(status_code=204)
    result.delete_cookie(settings.SESSION_COOKIE, path="/")
    return result


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/{path:path}")
async def frontend(path: str) -> Response:
    if path.startswith(("api/", "auth/")) or path == "healthz":
        raise HTTPException(status_code=404, detail="No encontrado.")
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        return Response("Construí el frontend con Docker Compose para iniciar el chat.", media_type="text/plain", status_code=503)
    return FileResponse(index)
