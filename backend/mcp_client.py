from __future__ import annotations

from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from backend.audit import record_event
from backend import settings


class MCPToolFailure(Exception):
    def __init__(self, message: str, *, kind: str = "unavailable"):
        super().__init__(message)
        self.kind = kind


def _structured(result: Any) -> dict[str, Any]:
    if result.is_error:
        details = " ".join(getattr(block, "text", "") for block in result.content).strip()
        normalized = details.lower()
        kind = "forbidden" if "política de acceso" in normalized else "conflict" if "confirmación" in normalized else "unavailable"
        raise MCPToolFailure("No fue posible completar la operación.", kind=kind)
    structured = result.structured_content
    if isinstance(structured, dict):
        if isinstance(structured.get("result"), dict):
            return structured["result"]
        return structured
    text = " ".join(getattr(block, "text", "") for block in result.content).strip()
    if text:
        return {"message": text}
    return {}


def _result_summary(name: str, result: dict[str, Any]) -> dict[str, Any]:
    if name == "search_kb":
        items = result.get("items", [])
        return {
            "authorized_items": len(items) if isinstance(items, list) else 0,
            "sources": [
                {
                    "id": str(item.get("source_id", "")),
                    "title": str(item.get("title", "")),
                    "approval_status": str(item.get("approval_status", "unknown")),
                }
                for item in items[:10]
                if isinstance(item, dict)
            ] if isinstance(items, list) else [],
        }
    if name == "get_my_ticket":
        ticket = result.get("ticket")
        return {
            "available": bool(result.get("available")),
            "ticket_id": ticket.get("id") if isinstance(ticket, dict) else None,
            "status": ticket.get("status") if isinstance(ticket, dict) else None,
            "authorization_bypassed": bool(result.get("authorization_bypassed")),
            "vulnerability_triggered": bool(result.get("vulnerability_triggered")),
        }
    if name == "list_user_groups":
        groups = result.get("groups", [])
        return {"available": bool(result.get("available")), "group_count": len(groups) if isinstance(groups, list) else 0}
    if name == "reset_user_mfa":
        return {"otp_credentials_removed": int(result.get("otp_credentials_removed", 0))}
    if name == "get_internal_product_pricing":
        return {"returned": bool(result.get("sku")), "sku": result.get("sku")}
    if name == "update_product_price":
        return {
            "updated": bool(result.get("updated")),
            "sku": result.get("sku"),
            "current_price_ars": result.get("current_price_ars"),
        }
    if name in {"prepare_support_ticket", "create_support_ticket"}:
        return {"ticket_id": result.get("ticket_id"), "status": result.get("status", "prepared")}
    return {"returned": True}


async def call_support_tool(
    access_token: str,
    name: str,
    arguments: dict[str, Any],
    *,
    audit_session: Any | None = None,
) -> dict[str, Any]:
    record_event(
        audit_session,
        category="tool",
        title=f"Invocación MCP · {name}",
        status="running",
        detail="El BFF envió argumentos al servidor MCP. El token de acceso no se registra.",
        payload={"tool": name, "arguments": arguments},
    )
    timeout = httpx2.Timeout(30.0)
    try:
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=timeout,
            follow_redirects=False,
        ) as http_client:
            transport = streamable_http_client(settings.MCP_INTERNAL_URL, http_client=http_client)
            async with Client(transport) as client:
                result = await client.call_tool(name, arguments)
        structured = _structured(result)
        result_summary = _result_summary(name, structured)
        authorization_bypassed = bool(result_summary.get("authorization_bypassed"))
        vulnerability_triggered = bool(result_summary.get("vulnerability_triggered"))
        record_event(
            audit_session,
            category="policy" if authorization_bypassed else "tool",
            title=f"{'Acceso vulnerable a objeto' if vulnerability_triggered else 'Autorización por objeto omitida' if authorization_bypassed else 'Respuesta MCP'} · {name}",
            status="vulnerable" if authorization_bypassed else "executed",
            detail=(
                "La herramienta devolvió un ticket sintético que habría sido denegado por propietario o cola."
                if vulnerability_triggered
                else "Modo vulnerable omitió OPA; el acceso seguiría permitido por propietario, rol o cola asignada."
                if authorization_bypassed
                else "La herramienta respondió. Se muestra un resumen, no el contenido completo de los registros."
            ),
            payload={"tool": name, "result": result_summary},
        )
        return structured
    except MCPToolFailure as exc:
        denied = exc.kind in {"forbidden", "conflict"}
        record_event(
            audit_session,
            category="policy" if denied else "tool",
            title=f"{'Decisión MCP/OPA' if denied else 'Fallo MCP'} · {name}",
            status="blocked" if denied else "error",
            detail=("MCP denegó la llamada o exigió una confirmación válida." if denied else "La herramienta no se completó."),
            payload={"tool": name, "reason": exc.kind},
        )
        raise
    except Exception as exc:
        # Do not leak bearer tokens or upstream error payloads into the chat response.
        record_event(
            audit_session,
            category="tool",
            title=f"Fallo de comunicación MCP · {name}",
            status="error",
            detail="El servidor MCP no respondió correctamente; no se registra el detalle upstream.",
            payload={"tool": name},
        )
        raise MCPToolFailure("El servidor MCP no está disponible o rechazó la solicitud.") from exc
