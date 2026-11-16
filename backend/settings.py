from __future__ import annotations

import os


def env(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


APP_ORIGIN = env("APP_ORIGIN", "http://localhost:8000")
KEYCLOAK_PUBLIC_URL = env("KEYCLOAK_PUBLIC_URL", "http://localhost:8080").rstrip("/")
KEYCLOAK_INTERNAL_URL = env("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
REALM = env("KEYCLOAK_REALM", "support-poc")
OIDC_ISSUER = f"{KEYCLOAK_PUBLIC_URL}/realms/{REALM}"
OIDC_INTERNAL_REALM = f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}"
OIDC_CLIENT_ID = env("OIDC_CLIENT_ID", "agent-bff")
OIDC_CLIENT_SECRET = env("OIDC_CLIENT_SECRET", "local-only-agent-bff-secret")
OIDC_REDIRECT_URI = env("OIDC_REDIRECT_URI", f"{APP_ORIGIN}/auth/callback")
COOKIE_SECURE = env("COOKIE_SECURE", "false").lower() == "true"
MCP_INTERNAL_URL = env("MCP_INTERNAL_URL", "http://mcp:8002/mcp")
ACTION_SIGNING_SECRET = env("APP_ACTION_SECRET", "local-only-change-this-action-secret")
SESSION_COOKIE = "support_session"
OIDC_STATE_COOKIE = "oidc_state"
SESSION_TTL_SECONDS = 30 * 60
MAX_CHAT_LENGTH = 1200
MAX_RESULTS = 5
LLM_BASE_URL = "http://ollama:11434/v1"
LLM_MODEL = env("LLM_MODEL", "qwen3.5:2b")
LLM_LOCAL = env("LLM_LOCAL", "true").lower() == "true"
LLM_ENABLED = LLM_LOCAL
LLM_TIMEOUT_SECONDS = float(env("LLM_TIMEOUT_SECONDS", "60" if LLM_LOCAL else "12"))
LLM_TOOL_CALLING_ENABLED = env("LLM_TOOL_CALLING_ENABLED", "true").lower() == "true"
GROUPS_DEMO_MODE = env("GROUPS_DEMO_MODE", "vulnerable").lower()
if GROUPS_DEMO_MODE not in {"secure", "vulnerable"}:
    raise ValueError("GROUPS_DEMO_MODE debe ser 'secure' o 'vulnerable'.")
PROMPT_INJECTION_DEMO_MODE = env("PROMPT_INJECTION_DEMO_MODE", "vulnerable").lower()
if PROMPT_INJECTION_DEMO_MODE not in {"secure", "vulnerable"}:
    raise ValueError("PROMPT_INJECTION_DEMO_MODE debe ser 'secure' o 'vulnerable'.")
DEMO_MODE_CONTROL_ENABLED = env("DEMO_MODE_CONTROL_ENABLED", "false").lower() == "true"
KEYCLOAK_MFA_RESET_ENABLED = env("KEYCLOAK_MFA_RESET_ENABLED", "false").lower() == "true"
KEYCLOAK_MFA_ADMIN_CLIENT_ID = env("KEYCLOAK_MFA_ADMIN_CLIENT_ID", "mcp-mfa-operator")
KEYCLOAK_MFA_ADMIN_CLIENT_SECRET = env(
    "KEYCLOAK_MFA_ADMIN_CLIENT_SECRET", "local-only-mcp-mfa-operator-secret"
)
