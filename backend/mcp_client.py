from __future__ import annotations

from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

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


async def call_support_tool(access_token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
        return _structured(result)
    except MCPToolFailure:
        raise
    except Exception as exc:
        # Do not leak bearer tokens or upstream error payloads into the chat response.
        raise MCPToolFailure("El servidor MCP no está disponible o rechazó la solicitud.") from exc
