from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


MAX_EVENT_TEXT = 5000
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_SECRET_VALUE_RE = re.compile(
    r"(?i)\b(authorization|access[_-]?token|refresh[_-]?token|token|client[_-]?secret|secret|"
    r"password|passcode|verification[_-]?code|otp[_-]?code|api[_-]?key|approval[_-]?proof|cookie)\b(\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_SENSITIVE_KEYS = (
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
    "passcode",
    "api_key",
    "approval_proof",
    "cookie",
)


def _redact(value: Any, key: str = "") -> Any:
    if any(secret_key in key.casefold() for secret_key in _SENSITIVE_KEYS):
        return "[OCULTO]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        safe = _BEARER_RE.sub("Bearer [OCULTO]", value)
        safe = _JWT_RE.sub("[JWT OCULTO]", safe)
        safe = _SECRET_VALUE_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[OCULTO]", safe)
        if len(safe) > MAX_EVENT_TEXT:
            safe = safe[: MAX_EVENT_TEXT - 1] + "…"
        return safe
    return value


def record_event(
    session: Any,
    *,
    category: str,
    title: str,
    status: str = "info",
    detail: str = "",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep a bounded, redacted event stream on the authenticated session."""
    if session is None:
        return {}
    session.audit_sequence += 1
    event = {
        "id": session.audit_sequence,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "category": category,
        "title": title,
        "status": status,
        "detail": _redact(detail),
        "payload": _redact(payload or {}),
    }
    session.audit_events.append(event)
    for subscriber in tuple(session.audit_subscribers):
        if subscriber.full():
            try:
                subscriber.get_nowait()
            except Exception:
                pass
        try:
            subscriber.put_nowait(event)
        except Exception:
            pass
    return event
