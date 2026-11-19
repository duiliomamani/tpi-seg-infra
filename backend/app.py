from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import settings
from backend.audit import record_event
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
    make_mfa_reset_approval_proof,
    make_product_price_approval_proof,
    require_csrf,
)
from backend.mcp_client import MCPToolFailure, call_support_tool
from backend.store import PRODUCT_SKUS, get_demo_modes, initialize, set_demo_modes


initialize()
logger = logging.getLogger("support.audit")

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


class ConfirmActionInput(BaseModel):
    summary: str = Field(min_length=6, max_length=120)
    description: str = Field(min_length=12, max_length=700)


class DemoModeInput(BaseModel):
    mode: Literal["secure", "vulnerable"]


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
    demo_modes = get_demo_modes()
    return {
        "authenticated": True,
        "name": session.display_name,
        "email": session.email,
        "roles": session.roles,
        "model_configured": settings.LLM_ENABLED,
        "model_local": settings.LLM_LOCAL,
        **demo_modes,
        "demo_control_enabled": settings.DEMO_MODE_CONTROL_ENABLED,
        "csrf_token": session.csrf_token,
    }


@app.post("/api/demo/mode")
async def update_demo_mode(request: Request, body: DemoModeInput) -> dict[str, object]:
    _, session = current_session(request)
    require_csrf(request, session)
    if not settings.DEMO_MODE_CONTROL_ENABLED:
        raise HTTPException(status_code=404, detail="El control del laboratorio está deshabilitado.")
    modes = set_demo_modes(body.mode)
    logger.info(
        json.dumps(
            {
                "event": "demo_mode_changed",
                "subject": session.subject,
                "mode": body.mode,
            },
            separators=(",", ":"),
        )
    )
    return {"mode": body.mode, **modes}


@app.post("/api/consent/tool")
async def set_tool_consent(request: Request, body: ToolConsentInput) -> dict[str, object]:
    _, session = current_session(request)
    require_csrf(request, session)
    if body.allowed:
        session.consented_tools.add(body.tool)
    else:
        session.consented_tools.discard(body.tool)
    record_event(
        session,
        category="tool",
        title=f"Consentimiento {'otorgado' if body.allowed else 'rechazado'} · {body.tool}",
        status="authorized" if body.allowed else "denied",
        detail="La herramienta podrá ejecutarse durante esta sesión." if body.allowed else "La herramienta no se ejecutará sin consentimiento.",
        payload={"tool": body.tool},
    )
    return {"consented_tools": sorted(session.consented_tools)}


@app.post("/api/chat")
async def chat(request: Request, body: ChatInput) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    enforce_rate_limit(session)
    for action_id, pending in list(session.pending_actions.items()):
        if pending["expires_at"] < time.time():
            session.pending_actions.pop(action_id, None)
    message = body.message.strip()
    try:
        token = await get_mcp_access_token(session)
        result = await respond(message, session_id, session, token)
    except Exception:
        record_event(
            session,
            category="system",
            title="Falló el procesamiento de la consulta",
            status="error",
            detail="El BFF no pudo completar la consulta. El detalle interno no se expone en el registro.",
        )
        raise
    record_event(
        session,
        category="system",
        title="Consulta procesada por el BFF",
        status="awaiting_consent" if result.get("kind") == "tool_consent" else "completed",
        detail="El agente terminó de preparar la respuesta. Las llamadas a herramientas aparecen como eventos separados.",
        payload={"result_kind": result.get("kind"), "model_status": result.get("model_status")},
    )
    return result


@app.get("/api/logs/stream")
async def stream_session_logs(request: Request) -> StreamingResponse:
    session_id, session = current_session(request)
    queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=100)
    session.audit_subscribers.add(queue)

    async def events():
        try:
            snapshot = list(session.audit_events)
            yield f"event: snapshot\ndata: {json.dumps(snapshot, ensure_ascii=False, separators=(',', ':'))}\n\n"
            while SESSIONS.get(session_id) is session and not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"event: log\ndata: {json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n\n"
        finally:
            session.audit_subscribers.discard(queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@app.post("/api/actions/{action_id}/confirm")
async def confirm_action(request: Request, action_id: str, body: ConfirmActionInput) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    pending = session.pending_actions.get(action_id)
    if not pending or pending.get("kind", "ticket") != "ticket" or pending["expires_at"] < time.time():
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
            audit_session=session,
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
        "trace": [
            {"stage": "Confirmación autenticada", "status": "allowed", "detail": "El contenido revisado coincide con la aprobación vigente."},
            {"stage": "MCP / OPA · ticket:create", "status": "allowed", "detail": "La política autorizó crear el ticket para esta sesión."},
            {"stage": "Cola de soporte", "status": "executed", "detail": "El ticket quedó creado en el fixture local."},
        ],
    }


@app.post("/api/actions/{action_id}/confirm-mfa-reset")
async def confirm_mfa_reset(request: Request, action_id: str) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    pending = session.pending_actions.get(action_id)
    if not pending or pending.get("kind") != "mfa_reset" or pending["expires_at"] < time.time():
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="La solicitud de reset MFA venció. Volvé a iniciarla.")
    if "support_admin" not in session.roles:
        raise HTTPException(status_code=403, detail="Sólo soporte administrador puede confirmar el reset MFA.")
    username = str(pending.get("username", ""))
    if username not in {"alice", "bob", "soporte"}:
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="La cuenta sintética no es válida.")
    expires_at = min(int(pending["expires_at"]), int(time.time() + 180))
    proof = make_mfa_reset_approval_proof(session_id, session.subject, action_id, username, expires_at)
    token = await get_mcp_access_token(session)
    try:
        result = await call_support_tool(
            token,
            "reset_user_mfa",
            {"username": username, "approval_proof": proof},
            audit_session=session,
        )
    except MCPToolFailure as exc:
        if exc.kind == "forbidden":
            raise HTTPException(status_code=403, detail="La política no autorizó resetear el MFA de esa cuenta.") from exc
        if exc.kind == "conflict":
            raise HTTPException(status_code=409, detail="La confirmación venció o no coincide con la solicitud.") from exc
        raise HTTPException(status_code=503, detail="No se pudo completar el reset MFA en Keycloak local.") from exc
    session.pending_actions.pop(action_id, None)
    removed = int(result.get("otp_credentials_removed", 0))
    outcome = (
        f"Se eliminaron {removed} credenciales OTP de Keycloak y se requiere volver a configurarlas."
        if removed
        else "La cuenta no tenía una credencial OTP activa; quedó marcada para configurar MFA al próximo ingreso."
    )
    return {
        "kind": "message",
        "text": f"Reset MFA aplicado en el realm local support-poc para {username}. {outcome}",
        "sources": [{"id": f"MFA-{username.upper()}", "title": "MFA del realm sintético support-poc"}],
        "trace": [
            {"stage": "Confirmación autenticada", "status": "allowed", "detail": "La confirmación vigente corresponde al sujeto y a la cuenta elegida."},
            {"stage": "MCP / OPA · mfa:reset", "status": "allowed", "detail": "La política autorizó la operación sensible tras validar el rol y el recurso."},
            {"stage": "Keycloak · support-poc", "status": "executed", "detail": outcome},
        ],
    }


@app.post("/api/actions/{action_id}/confirm-product-price")
async def confirm_product_price(request: Request, action_id: str) -> dict[str, object]:
    session_id, session = current_session(request)
    require_csrf(request, session)
    pending = session.pending_actions.get(action_id)
    if not pending or pending.get("kind") != "product_price" or pending["expires_at"] < time.time():
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="La solicitud de cambio de precio venció. Volvé a iniciarla.")
    if get_demo_modes()["product_data_demo_mode"] != "secure":
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="El modo del laboratorio cambió; revisá la solicitud antes de continuar.")
    if "support_admin" not in session.roles:
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=403, detail="Sólo soporte administrador puede confirmar cambios de precio.")
    sku = str(pending.get("sku", ""))
    new_price_ars = pending.get("new_price_ars")
    if sku not in PRODUCT_SKUS or type(new_price_ars) is not int or new_price_ars < 0:
        session.pending_actions.pop(action_id, None)
        raise HTTPException(status_code=409, detail="El producto o el precio de la solicitud no es válido.")
    expires_at = min(int(pending["expires_at"]), int(time.time() + 180))
    proof = make_product_price_approval_proof(
        session_id, session.subject, action_id, sku, new_price_ars, expires_at
    )
    token = await get_mcp_access_token(session)
    try:
        result = await call_support_tool(
            token,
            "update_product_price",
            {"sku": sku, "new_price_ars": new_price_ars, "approval_proof": proof},
            audit_session=session,
        )
    except MCPToolFailure as exc:
        if exc.kind == "forbidden":
            session.pending_actions.pop(action_id, None)
            raise HTTPException(status_code=403, detail="MCP/OPA denegó el cambio de precio o el valor está fuera de la política comercial.") from exc
        if exc.kind == "conflict":
            session.pending_actions.pop(action_id, None)
            raise HTTPException(status_code=409, detail="La confirmación venció o no coincide con el cambio solicitado.") from exc
        raise HTTPException(status_code=503, detail="No se pudo confirmar el cambio en el catálogo local.") from exc
    session.pending_actions.pop(action_id, None)
    updated_price_ars = int(result.get("current_price_ars", new_price_ars))
    formatted_price = f"${updated_price_ars:,}".replace(",", ".")
    return {
        "kind": "message",
        "text": f"Precio actualizado para {result.get('product_name', sku)} ({sku}): {formatted_price} ARS.",
        "sources": [{"id": sku, "title": "Catálogo sintético de precios"}],
        "trace": [
            {"stage": "Confirmación autenticada", "status": "allowed", "detail": "La firma vigente coincide con el sujeto, el SKU y el precio revisado."},
            {"stage": "MCP / OPA · pricing:update", "status": "allowed", "detail": "MCP verificó la firma y OPA autorizó rol, recurso y precio mínimo."},
            {"stage": "Catálogo sintético", "status": "executed", "detail": "El precio se actualizó únicamente en la base local de fixtures."},
        ],
    }


@app.post("/api/actions/{action_id}/cancel")
async def cancel_action(request: Request, action_id: str) -> dict[str, str]:
    _, session = current_session(request)
    require_csrf(request, session)
    pending = session.pending_actions.pop(action_id, None)
    if pending:
        record_event(
            session,
            category="tool",
            title="Acción pendiente cancelada",
            status="cancelled",
            detail="La acción se canceló antes de invocar MCP.",
            payload={"kind": pending.get("kind"), "username": pending.get("username"), "sku": pending.get("sku")},
        )
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
