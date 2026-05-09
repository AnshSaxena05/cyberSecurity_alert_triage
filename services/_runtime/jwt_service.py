"""
HS256 service-token sign/verify.

Two trust planes:

1. **External user JWT** (Browser ↔ Next.js BFF) — minted at the BFF,
   verified at the BFF, never crosses into Python services. Out of
   scope for this module.

2. **Internal service JWT** (BFF ↔ FastAPI/worker, BFF ↔ NATS publish,
   Worker ↔ Worker) — HS256 with rotated symmetric secrets. This module
   handles minting and verification for plane (2).

Compensating controls for the wider trust radius of HS256:
  - Distinct secrets per audience (worker / ingest / gateway).
  - Aggressive rotation (default 24h) with overlap window.
  - Strict ``aud`` claim — verifiers reject mismatched audience.
  - Per-batch verify cache so 10k msg/sec doesn't pay verify CPU on
    every message.
  - Revocation deny-list (``revoked_jti:{jti}``) checked on every verify.

Concurrency:
  - ``mint`` is pure CPU; safe to call from anywhere.
  - ``verify`` reads Redis (deny-list) and is async; cache wraps the hot
    path. Safe to call from N consumers concurrently.
  - Secret rotation: holders carry both ``current`` and ``previous`` secrets
    during the overlap window; verify tries current first, then previous.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import jwt as pyjwt  # PyJWT
import structlog

from services._runtime.tenant import AuthContext

logger = structlog.get_logger(__name__)

_DEFAULT_TTL_SEC = 5 * 60   # 5 min for service tokens
_DEFAULT_LEEWAY_SEC = 30    # clock skew tolerance


class JWTError(Exception):
    """Raised when a token is invalid, expired, audience-mismatched, or revoked."""


@dataclass
class SecretBundle:
    """
    Two-key bundle to support seamless rotation.

    During the overlap window after a rotation, ``previous`` is still
    accepted on verify but never used for new signatures.
    """

    audience: str                                # e.g. "worker", "ingest"
    current: str                                 # active signing secret (raw)
    previous: str | None = None                  # accepted on verify only
    rotated_at: float = field(default_factory=time.time)


@dataclass
class _CacheEntry:
    payload: dict[str, Any]
    audience: str
    expires_at: float


class JWTService:
    """
    Mint and verify HS256 service tokens.

    Construct with the audience this instance is responsible for and a
    function that returns the current ``SecretBundle`` (so rotation can
    swap the bundle without reconstructing the service).
    """

    def __init__(
        self,
        audience: str,
        bundle_provider,                         # () -> SecretBundle
        revoked_jti_checker=None,                # async fn(jti) -> bool, may be None
        token_ttl_seconds: int = _DEFAULT_TTL_SEC,
        leeway_seconds: int = _DEFAULT_LEEWAY_SEC,
    ) -> None:
        self._audience = audience
        self._provider = bundle_provider
        self._revoked = revoked_jti_checker
        self._ttl = token_ttl_seconds
        self._leeway = leeway_seconds
        # Per-jti cache. Lifetime bounded by token expiry; eviction is lazy.
        self._cache: dict[str, _CacheEntry] = {}
        self._cache_max_entries = 10_000

    # ---------- Mint ---------------------------------------------------

    def mint(
        self,
        *,
        subject: str,
        tenant_id: str,
        target_audience: str,
        role: str | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Sign a service token. ``target_audience`` is what the verifier
        will check (e.g. mint with target=``worker`` to call the worker).
        """
        bundle = self._provider()
        if bundle.audience != self._audience:
            raise JWTError(
                f"bundle audience {bundle.audience!r} does not match "
                f"service audience {self._audience!r}"
            )
        now = int(time.time())
        jti = _new_jti()
        claims: dict[str, Any] = {
            "iss": self._audience,
            "sub": subject,
            "aud": target_audience,
            "tid": tenant_id,
            "jti": jti,
            "iat": now,
            "exp": now + self._ttl,
        }
        if role is not None:
            claims["role"] = role
        if extra_claims:
            for k, v in extra_claims.items():
                if k in claims:
                    raise JWTError(f"extra_claims may not override reserved claim {k!r}")
                claims[k] = v
        return pyjwt.encode(claims, bundle.current, algorithm="HS256")

    # ---------- Verify -------------------------------------------------

    async def verify(self, token: str) -> AuthContext:
        """
        Verify a token issued for this service's audience. Returns a
        populated ``AuthContext`` on success; raises ``JWTError`` on any
        failure (bad signature, expired, wrong audience, revoked, etc.).

        Uses a per-jti cache: if we've recently verified this exact token,
        we skip the signature check. Cache entry is bounded by the token's
        own ``exp``, so no entry outlives its token.
        """
        cached = self._cache.get(token)
        if cached is not None and cached.expires_at > time.time():
            await self._check_revocation(cached.payload.get("jti"))
            return _to_auth(cached.payload, cached.audience)

        bundle = self._provider()
        payload = self._decode_with_rotation(token, bundle)

        # Audience is the strictest check after signature.
        aud = payload.get("aud")
        if aud != self._audience:
            raise JWTError(f"audience mismatch: token aud={aud!r}, expected {self._audience!r}")

        # Required claims.
        for required in ("sub", "tid", "jti", "iat", "exp"):
            if required not in payload:
                raise JWTError(f"missing required claim {required!r}")

        await self._check_revocation(payload["jti"])

        self._maybe_evict()
        self._cache[token] = _CacheEntry(
            payload=payload,
            audience=self._audience,
            expires_at=float(payload["exp"]),
        )
        return _to_auth(payload, self._audience)

    # ---------- Helpers ------------------------------------------------

    def _decode_with_rotation(self, token: str, bundle: SecretBundle) -> dict[str, Any]:
        """Try current secret, then previous secret during overlap window."""
        last_err: Exception | None = None
        for secret in (bundle.current, bundle.previous):
            if not secret:
                continue
            try:
                return pyjwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    audience=self._audience,
                    leeway=self._leeway,
                    options={"require": ["exp", "iat", "sub", "aud", "tid", "jti"]},
                )
            except pyjwt.PyJWTError as exc:
                last_err = exc
        raise JWTError(f"token verification failed: {last_err}") from last_err

    async def _check_revocation(self, jti: str | None) -> None:
        if not jti or self._revoked is None:
            return
        try:
            revoked = await self._revoked(jti)
        except Exception as exc:
            logger.warning("jwt_revocation_check_failed", error=str(exc))
            return
        if revoked:
            self._cache.pop(jti, None)
            raise JWTError(f"token revoked (jti={jti!r})")

    def _maybe_evict(self) -> None:
        if len(self._cache) < self._cache_max_entries:
            return
        # Evict expired first; if still over budget, drop oldest by exp.
        now = time.time()
        expired = [k for k, v in self._cache.items() if v.expires_at <= now]
        for k in expired:
            self._cache.pop(k, None)
        if len(self._cache) >= self._cache_max_entries:
            oldest = sorted(self._cache.items(), key=lambda kv: kv[1].expires_at)
            for k, _ in oldest[: len(oldest) // 4]:
                self._cache.pop(k, None)


def _to_auth(payload: dict[str, Any], audience: str) -> AuthContext:
    return AuthContext(
        user_id=payload.get("sub"),
        tenant_id=str(payload["tid"]),
        audience=audience,
        role=payload.get("role"),
        jti=payload.get("jti"),
    )


def _new_jti() -> str:
    import secrets

    return secrets.token_urlsafe(16)
