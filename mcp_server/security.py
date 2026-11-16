from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Any

import httpx
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from backend import settings

logger = logging.getLogger("support.audit")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181").rstrip("/")
MCP_RESOURCE_URL = os.getenv("MCP_RESOURCE_URL", "http://localhost:8002/mcp")
_jwks = jwt.PyJWKClient(f"{settings.OIDC_INTERNAL_REALM}/protocol/openid-connect/certs")


def _decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        signing_key = _jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="mcp-support",
            issuer=settings.OIDC_ISSUER,
            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
        )
    except jwt.PyJWTError:
        return None
    if claims.get("azp") != settings.OIDC_CLIENT_ID:
        return None
    scopes = set(str(claims.get("scope", "")).split())
    if "support:read" not in scopes:
        return None
    if int(claims.get("exp", 0)) <= time.time():
        return None
    return claims


class KeycloakTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        claims = await asyncio.to_thread(_decode_access_token, token)
        if not claims:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp", "")),
            subject=str(claims["sub"]),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=MCP_RESOURCE_URL,
            claims=claims,
        )


async def policy_decision(
    *,
    action: str,
    subject: dict[str, Any],
    resource: dict[str, Any],
) -> tuple[bool, str]:
    payload = {"input": {"action": action, "subject": subject, "resource": resource}}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.post(f"{OPA_URL}/v1/data/support/allow", json=payload)
            response.raise_for_status()
            result = response.json().get("result", False)
            return result is True, "policy"
    except (httpx.HTTPError, ValueError):
        return False, "policy_unavailable"


def verified_subject(access: AccessToken | None) -> dict[str, Any] | None:
    if not access or not access.claims:
        return None
    claims = access.claims
    roles = claims.get("realm_access", {}).get("roles", [])
    assigned = claims.get("assigned_queues", [])
    if isinstance(assigned, str):
        assigned = [assigned]
    return {
        "sub": str(claims.get("sub", "")),
        "roles": [role for role in roles if role in {"employee", "support_l1", "support_admin"}],
        "assigned_queues": [str(queue) for queue in assigned],
        "active": bool(claims.get("active", True)),
    }


def audit(tool: str, subject: str, resource_id: str, allowed: bool, reason: str) -> None:
    logger.info(
        json.dumps(
            {
                "event": "tool_authorization",
                "request_id": uuid.uuid4().hex,
                "subject": subject,
                "tool": tool,
                "resource": resource_id,
                "decision": "allow" if allowed else "deny",
                "decision_source": reason,
            },
            separators=(",", ":"),
        )
    )


def audit_invocation(tool: str, subject: str) -> None:
    logger.info(
        json.dumps(
            {"event": "tool_invocation", "request_id": uuid.uuid4().hex, "subject": subject, "tool": tool},
            separators=(",", ":"),
        )
    )


def verify_approval_proof(
    proof: str,
    *,
    subject: str,
    summary: str,
    description: str,
) -> dict[str, Any] | None:
    try:
        encoded, signature_text = proof.split(".", 1)
        expected = hmac.new(
            settings.ACTION_SIGNING_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
        ).digest()
        supplied = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
        if not hmac.compare_digest(expected, supplied):
            return None
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    expiry = payload.get("exp")
    if (
        payload.get("sub") != subject
        or payload.get("action") != "ticket:create"
        or payload.get("summary") != summary
        or payload.get("description") != description
        or not isinstance(payload.get("session"), str)
        or not payload.get("session")
        or not isinstance(payload.get("action_id"), str)
        or not payload.get("action_id")
        or not isinstance(expiry, int)
        or expiry < time.time()
        or expiry > time.time() + 300
    ):
        return None
    return payload


def verify_mfa_reset_approval_proof(
    proof: str,
    *,
    subject: str,
    username: str,
) -> dict[str, Any] | None:
    try:
        encoded, signature_text = proof.split(".", 1)
        expected = hmac.new(
            settings.ACTION_SIGNING_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
        ).digest()
        supplied = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
        if not hmac.compare_digest(expected, supplied):
            return None
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    expiry = payload.get("exp")
    if (
        payload.get("sub") != subject
        or payload.get("action") != "mfa:reset"
        or payload.get("username") != username
        or not isinstance(payload.get("session"), str)
        or not payload.get("session")
        or not isinstance(payload.get("action_id"), str)
        or not payload.get("action_id")
        or not isinstance(expiry, int)
        or expiry < time.time()
        or expiry > time.time() + 300
    ):
        return None
    return payload
