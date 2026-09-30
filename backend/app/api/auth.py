"""Supabase Auth verification for FastAPI bearer tokens."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.errors import ApiError

_BEARER = HTTPBearer(auto_error=False, scheme_name="SupabaseAccessToken", bearerFormat="JWT")


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    id: str


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> AuthenticatedUser | None: ...


class SupabaseTokenVerifier:
    """Ask Supabase Auth to validate the access JWT and load its user record."""

    def __init__(self, supabase_client: object) -> None:
        self._client = supabase_client

    async def verify(self, token: str) -> AuthenticatedUser | None:
        try:
            response = await self._client.auth.get_user(token)
        except Exception as exc:
            status = getattr(exc, "status", None) or getattr(exc, "status_code", None)
            if status in {400, 401, 403}:
                return None
            # The Auth service/network may be unavailable. Do not misreport that
            # infrastructure failure as an invalid credential or log the token.
            raise ApiError(
                503,
                "authentication_unavailable",
                "Authentication could not be verified right now.",
            ) from None

        user = getattr(response, "user", None) if response is not None else None
        user_id = getattr(user, "id", None)
        if not isinstance(user_id, str):
            return None
        try:
            canonical_id = str(UUID(user_id))
        except (ValueError, AttributeError):
            return None
        return AuthenticatedUser(id=canonical_id)


async def get_authenticated_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.casefold() != "bearer" or not credentials.credentials:
        raise ApiError(
            401,
            "unauthorized",
            "A valid Supabase access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    verifier: TokenVerifier | None = request.app.state.token_verifier
    if verifier is None:
        raise ApiError(503, "authentication_unavailable", "Authentication is not configured.")

    user = await verifier.verify(credentials.credentials)
    if user is None:
        raise ApiError(
            401,
            "unauthorized",
            "A valid Supabase access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
