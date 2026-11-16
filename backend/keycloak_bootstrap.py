from __future__ import annotations

import os
import sys
import time
from typing import Any

import httpx


BASE_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
POC_REALM = os.getenv("KEYCLOAK_REALM", "support-poc")
CLIENT_ID = os.getenv("KEYCLOAK_MFA_ADMIN_CLIENT_ID", "mcp-mfa-operator")
CLIENT_SECRET = os.getenv("KEYCLOAK_MFA_ADMIN_CLIENT_SECRET", "local-only-mcp-mfa-operator-secret")
BOOTSTRAP_USER = os.getenv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
BOOTSTRAP_PASSWORD = os.getenv("KC_BOOTSTRAP_ADMIN_PASSWORD", "local-only-admin-pass")
OPERATOR_ROLES = ("manage-users", "query-users", "view-users")
TIMEOUT = httpx.Timeout(10.0)


def _exactly_one(items: Any, label: str) -> dict[str, Any]:
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise RuntimeError(f"Keycloak no devolvió un único {label}.")
    return items[0]


def _admin_token(client: httpx.Client) -> str:
    response = client.post(
        f"{BASE_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": BOOTSTRAP_USER,
            "password": BOOTSTRAP_PASSWORD,
        },
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Keycloak no devolvió el token de bootstrap.")
    return token


def _get_json(client: httpx.Client, path: str) -> Any:
    response = client.get(f"{BASE_URL}/admin/realms/{path}")
    response.raise_for_status()
    return response.json()


def _ensure_operator(client: httpx.Client) -> None:
    realm_client = _exactly_one(
        _get_json(client, "master/clients?clientId=support-poc-realm"),
        "cliente de administración del realm PoC",
    )
    realm_client_id = realm_client.get("id")
    if not isinstance(realm_client_id, str) or not realm_client_id:
        raise RuntimeError("Keycloak no devolvió el identificador del cliente de administración.")

    existing = _get_json(client, f"master/clients?clientId={CLIENT_ID}")
    desired = {
        "clientId": CLIENT_ID,
        "name": "MCP local MFA reset operator",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": CLIENT_SECRET,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "fullScopeAllowed": False,
    }
    if existing:
        operator = _exactly_one(existing, "cliente operador MFA")
        operator_id = operator.get("id")
        if not isinstance(operator_id, str) or not operator_id:
            raise RuntimeError("Keycloak no devolvió el identificador del operador MFA.")
        operator.update(desired)
        response = client.put(f"{BASE_URL}/admin/realms/master/clients/{operator_id}", json=operator)
    else:
        response = client.post(f"{BASE_URL}/admin/realms/master/clients", json=desired)
        response.raise_for_status()
        operator = _exactly_one(
            _get_json(client, f"master/clients?clientId={CLIENT_ID}"),
            "cliente operador MFA",
        )
        operator_id = operator.get("id")
        if not isinstance(operator_id, str) or not operator_id:
            raise RuntimeError("Keycloak no devolvió el identificador del operador MFA.")
        response = None
    if response is not None:
        response.raise_for_status()

    service_account = _get_json(client, f"master/clients/{operator_id}/service-account-user")
    service_account_id = service_account.get("id") if isinstance(service_account, dict) else None
    if not isinstance(service_account_id, str) or not service_account_id:
        raise RuntimeError("Keycloak no creó la cuenta de servicio del operador MFA.")

    role_representations = []
    for role_name in OPERATOR_ROLES:
        role = _get_json(client, f"master/clients/{realm_client_id}/roles/{role_name}")
        if not isinstance(role, dict) or not role.get("id"):
            raise RuntimeError(f"No existe el rol requerido para la PoC: {role_name}.")
        role_representations.append(role)

    service_roles_path = (
        f"master/users/{service_account_id}/role-mappings/clients/{realm_client_id}"
    )
    current_service_roles = _get_json(client, service_roles_path)
    current_names = {
        role.get("name")
        for role in current_service_roles
        if isinstance(role, dict) and isinstance(role.get("name"), str)
    }
    missing_service_roles = [role for role in role_representations if role["name"] not in current_names]
    if missing_service_roles:
        response = client.post(
            f"{BASE_URL}/admin/realms/{service_roles_path}", json=missing_service_roles
        )
        response.raise_for_status()

    scope_roles_path = f"master/clients/{operator_id}/scope-mappings/clients/{realm_client_id}"
    current_scope_roles = _get_json(client, scope_roles_path)
    current_scope_names = {
        role.get("name")
        for role in current_scope_roles
        if isinstance(role, dict) and isinstance(role.get("name"), str)
    }
    missing_scope_roles = [role for role in role_representations if role["name"] not in current_scope_names]
    if missing_scope_roles:
        response = client.post(
            f"{BASE_URL}/admin/realms/{scope_roles_path}", json=missing_scope_roles
        )
        response.raise_for_status()

    scopes = _get_json(client, "master/client-scopes")
    admin_api_scope = _exactly_one(
        [scope for scope in scopes if isinstance(scope, dict) and scope.get("name") == "kc-admin-api"],
        "scope kc-admin-api",
    )
    scope_id = admin_api_scope.get("id")
    if not isinstance(scope_id, str) or not scope_id:
        raise RuntimeError("Keycloak no devolvió el identificador del scope kc-admin-api.")
    response = client.put(
        f"{BASE_URL}/admin/realms/master/clients/{operator_id}/default-client-scopes/{scope_id}"
    )
    response.raise_for_status()


def main() -> int:
    if POC_REALM != "support-poc" or not CLIENT_ID or not CLIENT_SECRET:
        print("Configuración de bootstrap inválida para el realm local de la PoC.", file=sys.stderr)
        return 1

    deadline = time.monotonic() + 180
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with httpx.Client(timeout=TIMEOUT, trust_env=False) as client:
                client.headers["Authorization"] = f"Bearer {_admin_token(client)}"
                _ensure_operator(client)
            print("Keycloak: operador MFA de mínimo alcance listo para support-poc.")
            return 0
        except (httpx.HTTPError, RuntimeError, ValueError, TypeError) as exc:
            last_error = exc
            time.sleep(2)

    print(
        f"No se pudo inicializar el operador MFA de Keycloak: {type(last_error).__name__ if last_error else 'timeout'}.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
