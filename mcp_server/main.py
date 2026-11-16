from __future__ import annotations

import logging
import os
import re
from typing import Any

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError

from backend import settings
from backend.store import create_ticket, find_articles, find_ticket, find_user_groups, get_demo_modes, initialize
from mcp_server.keycloak_admin import KeycloakMFAResetError, reset_keycloak_mfa
from mcp_server.security import (
    KeycloakTokenVerifier,
    audit,
    audit_invocation,
    policy_decision,
    verified_subject,
    verify_approval_proof,
    verify_mfa_reset_approval_proof,
)


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
initialize()

MCP_RESOURCE_URL = os.getenv("MCP_RESOURCE_URL", "http://localhost:8002/mcp")
MCP_ISSUER_URL = settings.OIDC_ISSUER
mcp = MCPServer(
    "Support Desk MCP",
    instructions="Herramientas de soporte. La autorización de cada recurso se valida en el servidor MCP.",
    token_verifier=KeycloakTokenVerifier(),
    auth=AuthSettings(
        issuer_url=MCP_ISSUER_URL,
        resource_server_url=MCP_RESOURCE_URL,
        required_scopes=["support:read"],
        # Keycloak uses the mcp-support client audience, not RFC 8707's resource URI.
        # The verifier checks aud= mcp-support and binds the verified token to this URL.
        validate_token_resource=True,
    ),
)


def _subject() -> tuple[Any, dict[str, Any]]:
    access = get_access_token()
    subject = verified_subject(access)
    if not access or not subject:
        raise ToolError("No pudimos validar la identidad de esta solicitud.")
    return access, subject


@mcp.tool()
async def search_kb(query: str, category: str | None = None) -> dict[str, Any]:
    """Busca respuestas en artículos aprobados y autorizados de soporte."""
    access, subject = _subject()
    audit_invocation("search_kb", subject["sub"])
    if "support:read" not in access.scopes:
        raise ToolError("La sesión no tiene permiso de lectura.")
    if not query.strip() or len(query) > 400:
        raise ToolError("La consulta debe tener entre 1 y 400 caracteres.")
    if category and (len(category) > 40 or not re.fullmatch(r"[a-záéíóúñ_-]+", category.lower())):
        raise ToolError("La categoría no es válida.")

    candidates = find_articles(query, limit=12, include_unapproved_ids={"KB-MFA-INJECTION"})
    if category:
        candidates = [item for item in candidates if item["category"] == category.lower()]
    results: list[dict[str, str]] = []
    for article in candidates:
        resource = {
            "id": article["id"],
            "classification": article["classification"],
            "team": article["team"],
            "approved": bool(article["approved"]),
        }
        if article["id"] == "KB-MFA-INJECTION" and get_demo_modes()["prompt_injection_demo_mode"] == "vulnerable":
            # Deliberately lets an unapproved fixture cross the trust boundary in this local demo.
            allowed, reason = True, "demo_untrusted_context"
        else:
            allowed, reason = await policy_decision(action="kb:read", subject=subject, resource=resource)
        audit("search_kb", subject["sub"], article["id"], allowed, reason)
        if reason == "policy_unavailable":
            raise ToolError("No se pudo verificar el acceso en este momento.")
        if allowed:
            results.append(
                {
                    "source_id": article["id"],
                    "title": article["title"],
                    "text": article["body"][:1200],
                }
            )
        if len(results) == 5:
            break
    return {"items": results}


@mcp.tool()
async def get_my_ticket(ticket_id: str) -> dict[str, Any]:
    """Consulta un ticket propio o asignado a la cola del equipo de soporte."""
    access, subject = _subject()
    audit_invocation("get_my_ticket", subject["sub"])
    if "support:read" not in access.scopes:
        raise ToolError("La sesión no tiene permiso de lectura.")
    normalized = ticket_id.strip().upper()
    if not re.fullmatch(r"T-[0-9]{3,7}", normalized):
        raise ToolError("El identificador del ticket no es válido.")
    ticket = find_ticket(normalized)
    if not ticket:
        audit("get_my_ticket", subject["sub"], normalized, False, "not_found_or_forbidden")
        return {"available": False, "message": "No encontré un ticket disponible para tu usuario."}
    resource = {
        "id": ticket["id"],
        "owner_id": ticket["owner_id"],
        "queue": ticket["queue"],
        "status": ticket["status"],
    }
    allowed, reason = await policy_decision(action="ticket:read", subject=subject, resource=resource)
    audit("get_my_ticket", subject["sub"], normalized, allowed, reason)
    if not allowed:
        # The same response for missing and forbidden IDs avoids disclosing ticket existence.
        return {"available": False, "message": "No encontré un ticket disponible para tu usuario."}
    return {
        "available": True,
        "ticket": {
            "id": ticket["id"],
            "summary": ticket["summary"],
            "description": ticket["description"],
            "status": ticket["status"],
            "created_at": ticket["created_at"],
        },
    }


@mcp.tool()
async def list_user_groups(username: str) -> dict[str, Any]:
    """Consulta membresías sintéticas. El modo vulnerable omite OPA sólo para la demo local."""
    access, subject = _subject()
    audit_invocation("list_user_groups", subject["sub"])
    if "support:read" not in access.scopes:
        raise ToolError("La sesión no tiene permiso de lectura.")
    normalized = username.strip().casefold()
    if normalized not in {"alice", "bob", "soporte"}:
        raise ToolError("El usuario debe ser alice, bob o soporte.")
    target = find_user_groups(normalized)
    if not target:
        audit("list_user_groups", subject["sub"], normalized, False, "not_found")
        return {"available": False, "groups": []}

    if get_demo_modes()["groups_demo_mode"] == "vulnerable":
        # Deliberately reproduces the PoC's missing object-level authorization.
        allowed, reason = True, "demo_missing_authorization"
    else:
        resource = {
            "username": target["username"],
            "subject_id": target["subject_id"],
            "team_id": target["team_id"],
        }
        allowed, reason = await policy_decision(action="groups:read", subject=subject, resource=resource)

    audit("list_user_groups", subject["sub"], normalized, allowed, reason)
    if reason == "policy_unavailable":
        raise ToolError("La política de acceso no pudo verificarse; la consulta fue denegada.")
    if not allowed:
        raise ToolError("La política de acceso no autorizó consultar los grupos de esa persona.")
    return {"available": True, "username": normalized, "groups": target["groups"]}


@mcp.tool()
async def reset_user_mfa(username: str, approval_proof: str = "") -> dict[str, Any]:
    """Reset OTP on an allowlisted synthetic user in the local support-poc Keycloak realm."""
    access, subject = _subject()
    audit_invocation("reset_user_mfa", subject["sub"])
    if "support:write" not in access.scopes:
        raise ToolError("La sesión no tiene permiso para solicitar esta operación.")
    normalized = username.strip().casefold()
    if normalized not in {"alice", "bob", "soporte"}:
        raise ToolError("La persona debe ser alice, bob o soporte en el directorio sintético.")
    target = find_user_groups(normalized)
    if not target:
        audit("reset_user_mfa", subject["sub"], normalized, False, "not_found")
        return {"reset": False, "username": normalized, "keycloak_modified": False}

    if get_demo_modes()["prompt_injection_demo_mode"] == "vulnerable":
        allowed, reason = True, "demo_missing_authorization_and_confirmation"
        approval = None
    else:
        approval = verify_mfa_reset_approval_proof(
            approval_proof,
            subject=subject["sub"],
            username=normalized,
        )
        if not approval:
            audit("reset_user_mfa", subject["sub"], normalized, False, "missing_or_invalid_confirmation")
            if "support_admin" in subject["roles"]:
                raise ToolError("El restablecimiento requiere una confirmación autenticada vigente.")
            raise ToolError("La política de acceso no autorizó restablecer el MFA de esa persona.")
        resource = {
            "username": target["username"],
            "subject_id": target["subject_id"],
            "confirmed": True,
        }
        allowed, reason = await policy_decision(action="mfa:reset", subject=subject, resource=resource)

    if reason == "policy_unavailable":
        audit("reset_user_mfa", subject["sub"], normalized, False, reason)
        raise ToolError("La política de acceso no pudo verificarse; el restablecimiento fue denegado.")
    if not allowed:
        audit("reset_user_mfa", subject["sub"], normalized, False, reason)
        raise ToolError("La política de acceso no autorizó restablecer el MFA de esa persona.")

    try:
        reset_result = await reset_keycloak_mfa(normalized)
    except KeycloakMFAResetError as exc:
        audit("reset_user_mfa", subject["sub"], normalized, False, "keycloak_admin_failed")
        raise ToolError(str(exc)) from exc
    result_reason = "demo_vulnerable_bypass" if get_demo_modes()["prompt_injection_demo_mode"] == "vulnerable" else reason
    audit("reset_user_mfa", subject["sub"], normalized, True, result_reason)
    return {
        "reset": True,
        **reset_result,
    }


@mcp.tool()
async def create_support_ticket(summary: str, description: str, approval_proof: str) -> dict[str, Any]:
    """Crea un ticket sólo con una aprobación firmada por el BFF y el usuario."""
    access, subject = _subject()
    audit_invocation("create_support_ticket", subject["sub"])
    if "support:write" not in access.scopes:
        raise ToolError("La sesión no tiene permiso para crear tickets.")
    summary = summary.strip()
    description = description.strip()
    if not 6 <= len(summary) <= 120 or not 12 <= len(description) <= 700:
        raise ToolError("El resumen o la descripción no cumplen los límites permitidos.")
    proof = verify_approval_proof(
        approval_proof,
        subject=subject["sub"],
        summary=summary,
        description=description,
    )
    if not proof:
        audit("create_support_ticket", subject["sub"], "new-ticket", False, "invalid_confirmation")
        raise ToolError("La confirmación venció o no coincide con el contenido. Revisá la tarjeta y confirmá de nuevo.")
    resource = {
        "owner_id": subject["sub"],
        "queue": "network",
        "status": "Nuevo",
        "confirmed": True,
    }
    allowed, reason = await policy_decision(action="ticket:create", subject=subject, resource=resource)
    audit("create_support_ticket", subject["sub"], str(proof["action_id"]), allowed, reason)
    if reason == "policy_unavailable":
        raise ToolError("El servicio de políticas no está disponible; la operación fue denegada.")
    if not allowed:
        raise ToolError("La política de acceso no autorizó crear el ticket.")
    ticket = create_ticket(subject["sub"], summary, description, str(proof["action_id"]))
    return {"created": True, "ticket_id": ticket["id"], "status": ticket["status"]}


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.getenv("MCP_PORT", "8002")),
        stateless_http=True,
        json_response=True,
    )
