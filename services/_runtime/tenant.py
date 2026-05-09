"""
Tenant-id accessor.

The authoritative tenant_id for any request or NATS message is the value
in the verified service JWT (or the user JWT, when accessed at the BFF).
Never read tenant_id from the request body, the message body, or any
client-supplied field.

`scripts/lint_tenant_id.py` enforces this rule statically: any read of
`payload["tenant_id"]`, `body.tenant_id`, or `msg.data["tenant_id"]`
outside this module fails CI.

Concurrency: pure functions; no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


class TenantContextError(Exception):
    """Raised when an authenticated request is missing tenant_id."""


class _HasState(Protocol):
    state: Any


@dataclass(frozen=True)
class AuthContext:
    """
    Verified authentication claims attached to a request or NATS message.

    Populated by:
      - FastAPI auth dependency for HTTP requests (request.state.auth)
      - NATS message handler for service-to-service traffic (from JWT in
        message header, after `services._runtime.jwt_service.verify`)
    """

    user_id: str | None
    tenant_id: str
    audience: str
    role: str | None = None
    jti: str | None = None


def get_tenant_id(ctx: AuthContext | _HasState | Mapping[str, Any]) -> str:
    """
    Return the authoritative tenant_id from a verified auth context.

    Accepts:
      - An ``AuthContext`` directly.
      - A FastAPI ``Request`` (uses ``request.state.auth``).
      - A plain mapping with a verified ``"auth"`` entry (e.g. the dict
        passed into NATS message handlers after JWT verify).

    Raises ``TenantContextError`` if no verified auth context is present.
    Returns the tenant_id string. Never reads from request/message bodies.
    """
    auth = _extract_auth(ctx)
    if auth.tenant_id is None or not auth.tenant_id.strip():
        raise TenantContextError("auth context present but tenant_id is empty")
    return auth.tenant_id


def _extract_auth(ctx: AuthContext | _HasState | Mapping[str, Any]) -> AuthContext:
    if isinstance(ctx, AuthContext):
        return ctx
    if isinstance(ctx, Mapping):
        auth = ctx.get("auth")
        if isinstance(auth, AuthContext):
            return auth
        raise TenantContextError("mapping has no 'auth' AuthContext")
    state = getattr(ctx, "state", None)
    auth = getattr(state, "auth", None) if state is not None else None
    if isinstance(auth, AuthContext):
        return auth
    raise TenantContextError(
        "no AuthContext found; tenant_id must come from verified JWT, "
        "never from request/message body"
    )
