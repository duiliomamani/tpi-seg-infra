from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from backend import settings


DEMO_USERS = frozenset({"alice", "bob", "soporte"})
OTP_CREDENTIAL_TYPES = frozenset({"otp"})
REQUIRED_OTP_ACTION = "CONFIGURE_TOTP"


class KeycloakMFAResetError(Exception):
    pass


async def reset_keycloak_mfa(username: str) -> dict[str, Any]:
    """Remove TOTP credentials and require re-enrollment for a PoC realm user."""
    normalized = username.strip().casefold()
    if normalized not in DEMO_USERS:
        raise KeycloakMFAResetError("La cuenta no pertenece al directorio sintético.")
    if not settings.KEYCLOAK_MFA_RESET_ENABLED:
        raise KeycloakMFAResetError("El reset MFA de Keycloak está deshabilitado.")
    keycloak_url = urlsplit(settings.KEYCLOAK_INTERNAL_URL)
    if (
        settings.REALM != "support-poc"
        or keycloak_url.scheme != "http"
        or keycloak_url.hostname != "keycloak"
        or keycloak_url.port != 8080
        or keycloak_url.path not in {"", "/"}
    ):
        raise KeycloakMFAResetError("El reset sólo está habilitado para el Keycloak local del realm support-poc.")

    realm = quote(settings.REALM, safe="")
    base = settings.KEYCLOAK_INTERNAL_URL
    # The Keycloak Admin REST API accepts admin tokens issued by master.
    token_url = f"{base}/realms/master/protocol/openid-connect/token"
    admin_base = f"{base}/admin/realms/{realm}"

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            token_response = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": settings.KEYCLOAK_MFA_ADMIN_CLIENT_ID,
                    "client_secret": settings.KEYCLOAK_MFA_ADMIN_CLIENT_SECRET,
                },
            )
            token_response.raise_for_status()
            token = token_response.json().get("access_token")
            if not isinstance(token, str) or not token:
                raise KeycloakMFAResetError("Keycloak no devolvió un token de administración.")
            headers = {"Authorization": f"Bearer {token}"}

            users_response = await client.get(
                f"{admin_base}/users",
                params={"username": normalized, "exact": "true", "max": 2},
                headers=headers,
            )
            users_response.raise_for_status()
            users = users_response.json()
            if (
                not isinstance(users, list)
                or len(users) != 1
                or not isinstance(users[0], dict)
                or users[0].get("username", "").casefold() != normalized
            ):
                raise KeycloakMFAResetError("No se encontró una cuenta sintética única en el realm de la PoC.")
            user_id = users[0].get("id")
            if not isinstance(user_id, str) or not user_id:
                raise KeycloakMFAResetError("Keycloak no devolvió el identificador de la cuenta.")
            user_path = f"{admin_base}/users/{quote(user_id, safe='')}"

            user_response = await client.get(user_path, headers=headers)
            user_response.raise_for_status()
            user = user_response.json()
            if not isinstance(user, dict) or user.get("username", "").casefold() != normalized:
                raise KeycloakMFAResetError("La identidad de la cuenta de Keycloak no coincide.")

            current_actions = user.get("requiredActions", [])
            if not isinstance(current_actions, list):
                current_actions = []
            actions = list(dict.fromkeys([*current_actions, REQUIRED_OTP_ACTION]))
            action_added = REQUIRED_OTP_ACTION not in current_actions
            if action_added:
                for read_only in (
                    "access",
                    "createdTimestamp",
                    "credentials",
                    "disableableCredentialTypes",
                    "federatedIdentities",
                    "origin",
                    "self",
                    "userProfileMetadata",
                ):
                    user.pop(read_only, None)
                user["requiredActions"] = actions
                update_response = await client.put(user_path, json=user, headers=headers)
                update_response.raise_for_status()

            credentials_response = await client.get(f"{user_path}/credentials", headers=headers)
            credentials_response.raise_for_status()
            credentials = credentials_response.json()
            if not isinstance(credentials, list):
                raise KeycloakMFAResetError("Keycloak devolvió un listado de credenciales inválido.")

            otp_credentials = [
                item for item in credentials
                if isinstance(item, dict) and item.get("type") in OTP_CREDENTIAL_TYPES and item.get("id")
            ]
            removed = 0
            for credential in otp_credentials:
                delete_response = await client.delete(
                    f"{user_path}/credentials/{quote(str(credential['id']), safe='')}",
                    headers=headers,
                )
                delete_response.raise_for_status()
                removed += 1

    except KeycloakMFAResetError:
        raise
    except httpx.HTTPStatusError as exc:
        raise KeycloakMFAResetError(
            f"La API de administración de Keycloak rechazó la operación (HTTP {exc.response.status_code})."
        ) from exc
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise KeycloakMFAResetError("No se pudo completar el reset MFA en Keycloak.") from exc

    return {
        "username": normalized,
        "realm": settings.REALM,
        "keycloak_modified": bool(removed or action_added),
        "otp_credentials_removed": removed,
        "re_enrollment_required": True,
    }
